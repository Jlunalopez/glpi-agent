package GLPI::Agent::Task::Inventory::Win32::Users;

use strict;
use warnings;

use parent 'GLPI::Agent::Task::Inventory::Module';
use English qw(-no_match_vars);

use GLPI::Agent::Tools;
use GLPI::Agent::Tools::Win32;
use GLPI::Agent::Tools::Win32::Users;

use constant other_categories => qw(local_user local_group);
use constant category          => "user";

sub isEnabled {
    return 1;
}

# Cache for UPN lookups (performance optimization)
my %_upn_cache;

sub _getUPNFromSID {
    my ($sid, %params) = @_;
    return unless $sid && $sid =~ /^S-1-12-1-/;    # AzureAD/EntraID SIDs

    return $_upn_cache{$sid} if exists $_upn_cache{$sid};

    my $upn = getRegistryValue(
        path => "HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/IdentityStore/Cache/$sid/IdentityCache/$sid/UserName",
        %params
    );

    if ($upn && $upn =~ /.+@.+\..+/) {
        $_upn_cache{$sid} = $upn;
        return $upn;
    }

    return;
}

sub _resolveUserToUPN {
    my ($user, %params) = @_;
    my $login  = $user->{LOGIN}  || '';
    my $domain = $user->{DOMAIN} || '';

    # Case 1: Already a UPN
    if ($login =~ /^([^@]+)\@(.*)$/) {
        $user->{LOGIN}  = $1;
        $user->{DOMAIN} = $2;
        return $user;
    }

    # Case 2: AzureAD or local account with Azure SID
    if ($domain eq 'AzureAD' || $domain eq '.') {
        my $sid = $user->{SID};

        unless ($sid) {
            my ($account) = getUsers(login => $login, %params);
            $sid = $account->{SID} if $account;
        }

        if ($sid) {
            my $upn = _getUPNFromSID($sid, %params);
            if ($upn && $upn =~ /^([^@]+)\@(.*)$/) {
                $user->{LOGIN}     = $1;
                $user->{DOMAIN}    = $2;
                $user->{_fullname} = "$1\@$2";
                return $user;
            }
        }
    }

    # Case 3: Try to resolve via profile path
    if ($domain eq '.' || $domain !~ /\./) {
        if ($user->{SID}) {
            my $profile = getRegistryValue(
                path => "HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/ProfileList/$user->{SID}/ProfileImagePath",
                %params
            );

            if ($profile && $profile =~ /Users[\\/]([^\\\/]+)$/) {
                my $shortname = $1;
                my ($account) = getUsers(login => $shortname, %params);

                if ($account && $account->{SID} =~ /^S-1-12-1-/) {
                    my $upn = _getUPNFromSID($account->{SID}, %params);
                    if ($upn && $upn =~ /^([^@]+)\@(.*)$/) {
                        $user->{LOGIN}  = $1;
                        $user->{DOMAIN} = $2;
                        return $user;
                    }
                }
            }
        }
    }

    return $user;
}

sub _getLocalGroups {
    my %params = @_;

    my $query = "SELECT * FROM Win32_Group WHERE LocalAccount='True'";
    my @groups;

    foreach my $object (getWMIObjects(
        moniker    => 'winmgmts:\\\\.\\root\\CIMV2',
        query      => $query,
        properties => [qw/Name SID/],
        %params
    )) {
        $object->{Name} =~ s/\x{2019}/'/g;
        push @groups, {
            NAME => $object->{Name},
            ID   => $object->{SID},
        };
    }

    return @groups;
}

sub _getLoggedUsers {
    my %params = @_;

    my $query =
      "SELECT * FROM Win32_Process WHERE ExecutablePath IS NOT NULL AND ExecutablePath LIKE '%\\\\Explorer.exe'";

    my @users;

    foreach my $process (getWMIObjects(
        moniker    => 'winmgmts:\\\\.\\root\\CIMV2',
        query      => $query,
        properties => [qw/ProcessId/],
        %params
    )) {
        my $owner = getProcessOwner(pid => $process->{ProcessId}, %params);
        next unless $owner && $owner->{User};

        my $user = {
            LOGIN  => $owner->{User},
            DOMAIN => $owner->{Domain},
        };

        my ($account) = getUsers(login => $user->{LOGIN}, %params);
        $user->{SID} = $account->{SID} if $account;

        $user = _resolveUserToUPN($user, %params);
        push @users, $user;
    }

    return @users;
}

sub _getLastUser {
    my %params = @_;

    my $user;
    my ($system) = getWMIObjects(
        class      => 'Win32_ComputerSystem',
        properties => [qw/Name UserName/],
        %params
    );

    if ($system && $system->{UserName}) {
        my $username = $system->{UserName};
        $user = { DOMAIN => $system->{Name}, LOGIN => $username };

        if ($username =~ /^([^\\]+)\\(.*)$/) {
            $user->{DOMAIN} = $1;
            $user->{LOGIN}  = $2;
        }
    } else {
        foreach my $key (
            'SOFTWARE/Microsoft/Windows/CurrentVersion/Authentication/LogonUI/LastLoggedOnSAMUser',
            'SOFTWARE/Microsoft/Windows/CurrentVersion/Authentication/LogonUI/LastLoggedOnUser',
            'SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon/DefaultUserName',
          )
        {
            my $val = getRegistryValue(path => "HKEY_LOCAL_MACHINE/$key", %params);
            next unless $val;
            if ($val =~ /^([^\\]+)\\(.*)$/) {
                $user = { DOMAIN => $1, LOGIN => $2 };
            } else {
                $user = { DOMAIN => '.', LOGIN => $val };
            }
            last if $user;
        }
    }

    return unless $user && $user->{LOGIN};

    my ($account) = getUsers(login => $user->{LOGIN}, localusers => 1, %params);
    $user->{SID} = $account->{SID} if $account;

    $user = _resolveUserToUPN($user, %params);
    return $user;
}

sub _getLastLoggedAzureADUserUPN {
    my %params = @_;

    my $sid = getRegistryValue(
        path => "HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Authentication/LogonUI/LastLoggedOnUserSID",
        %params
    );
    return unless $sid;

    my $samname = getRegistryValue(
        path => "HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/IdentityStore/Cache/$sid/IdentityCache/$sid/SAMName",
        %params
    );
    return unless $samname && $params{name} && $samname eq $params{name};

    return getRegistryValue(
        path => "HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/IdentityStore/Cache/$sid/IdentityCache/$sid/UserName",
        %params
    );
}

sub doInventory {
    my (%params) = @_;
    my $inventory = $params{inventory};
    my $logger    = $params{logger};

    unless ($params{no_category}->{local_user}) {
        foreach my $user (getUsers(localusers => 1, logger => $logger)) {
            $inventory->addEntry(
                section => 'LOCAL_USERS',
                entry   => { map { $_ => $user->{$_} } qw/NAME ID/ }
            );
        }
    }

    unless ($params{no_category}->{local_group}) {
        foreach my $group (_getLocalGroups(logger => $logger)) {
            $inventory->addEntry(section => 'LOCAL_GROUPS', entry => $group);
        }
    }

    my %seen;
    my $lastLoggedUser = _getLastUser(logger => $logger);

    if ($lastLoggedUser) {
        my $fullname = delete $lastLoggedUser->{_fullname};
        $fullname = $fullname ? lc($fullname)
          : lc($lastLoggedUser->{LOGIN}) . '@' . lc($lastLoggedUser->{DOMAIN});

        $inventory->addEntry(section => 'USERS', entry => $lastLoggedUser)
          unless $seen{$fullname}++;

        # Legacy field (deprecated)
        $inventory->setHardware({ LASTLOGGEDUSER => $lastLoggedUser->{LOGIN} });
    }

    foreach my $user (_getLoggedUsers(logger => $logger)) {
        my $fullname = lc($user->{LOGIN}) . '@' . lc($user->{DOMAIN});
        $inventory->addEntry(section => 'USERS', entry => $user)
          unless $seen{$fullname}++;
    }
}

1;
