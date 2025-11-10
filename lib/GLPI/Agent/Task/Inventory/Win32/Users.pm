## User Info
# Current time: November 10, 2025 03:37 PM PST
# Country: US

package GLPI::Agent::Task::Inventory::Win32::Users;
use strict;
use warnings;
use parent 'GLPI::Agent::Task::Inventory::Module';
use English qw(-no_match_vars);
use GLPI::Agent::Tools;
use GLPI::Agent::Tools::Win32;
use GLPI::Agent::Tools::Win32::Users;

use constant other_categories => qw(local_user local_group);
use constant category         => "user";

sub isEnabled {
    return 1;
}

sub doInventory {
    my (%params) = @_;
    my $inventory = $params{inventory};
    my $logger    = $params{logger};

    # -----------------------------------------------------------------
    # Local Users
    # -----------------------------------------------------------------
    unless ($params{no_category}->{local_user}) {
        foreach my $user (getUsers(
            localusers => 1,
            logger     => $logger
        )) {
            $inventory->addEntry(
                section => 'LOCAL_USERS',
                entry   => { map { $_ => $user->{$_} } qw/NAME ID/ }
            );
        }
    }

    # -----------------------------------------------------------------
    # Local Groups
    # -----------------------------------------------------------------
    unless ($params{no_category}->{local_group}) {
        foreach my $group (_getLocalGroups(logger => $logger)) {
            $inventory->addEntry(
                section => 'LOCAL_GROUPS',
                entry   => $group
            );
        }
    }

    # -----------------------------------------------------------------
    # Track seen users (case-insensitive)
    # -----------------------------------------------------------------
    my %seen = ();

    # -----------------------------------------------------------------
    # Last Logged User
    # -----------------------------------------------------------------
    my $lastLoggedUser = _getLastUser(logger => $logger);
    if ($lastLoggedUser) {
        if (ref($lastLoggedUser) eq 'HASH') {
            my $fullname = delete $lastLoggedUser->{_fullname};

            # FORCE: login@company.org
            my $login = $lastLoggedUser->{LOGIN};
            $lastLoggedUser->{LOGIN}  = "$login\@company.org";
            $lastLoggedUser->{DOMAIN} = 'calstart.local';

            # Duplicate key uses the final LOGIN value
            $fullname = $fullname ? lc($fullname) : lc($lastLoggedUser->{LOGIN});

            $inventory->addEntry(
                section => 'USERS',
                entry   => $lastLoggedUser
            ) unless $seen{$fullname}++;

            # Legacy field (obsolete in GLPI 3.0+)
            $inventory->setHardware({
                LASTLOGGEDUSER => "$login\@company.org"
            });
        }
        else {
            # Legacy scalar case
            my ($login) = $lastLoggedUser =~ /^([^\\]+)/;
            $login //= $lastLoggedUser;
            my $forced = "$login\@company.org";

            $inventory->setHardware({
                LASTLOGGEDUSER => $forced
            });
        }
    }

    # -----------------------------------------------------------------
    # Currently Logged Users (from explorer.exe)
    # -----------------------------------------------------------------
    foreach my $user (_getLoggedUsers(logger => $logger)) {
        # FORCE: login@company.org
        my $login = $user->{LOGIN};
        $user->{LOGIN}  = "$login\@company.org";
        $user->{DOMAIN} = 'calstart.local';

        my $fullname = lc($user->{LOGIN});

        $inventory->addEntry(
            section => 'USERS',
            entry   => $user
        ) unless $seen{$fullname}++;
    }
}

# -----------------------------------------------------------------
# Local Groups via WMI
# -----------------------------------------------------------------
sub _getLocalGroups {
    my $query = "SELECT * FROM Win32_Group WHERE LocalAccount='True'";
    my @groups;

    foreach my $object (getWMIObjects(
        moniker    => 'winmgmts:\\\\.\\root\\CIMV2',
        query      => $query,
        properties => [ qw/Name SID/ ])
    ) {
        # Fix encoding issue
        $object->{Name} =~ s/\x{2019}/'/g;

        push @groups, {
            NAME => $object->{Name},
            ID   => $object->{SID},
        };
    }
    return @groups;
}

# -----------------------------------------------------------------
# Get users running explorer.exe
# -----------------------------------------------------------------
sub _getLoggedUsers {
    my $query = "SELECT * FROM Win32_Process"
              . " WHERE ExecutablePath IS NOT NULL"
              . " AND ExecutablePath LIKE '%\\\\Explorer\\.exe'";

    my @users;
    my $seen;

    foreach my $user (getWMIObjects(
        moniker  => 'winmgmts:\\\\.\\root\\CIMV2',
        query    => $query,
        method   => 'GetOwner',
        params   => [ 'User', 'Domain' ],
        User     => [ 'string', '' ],
        Domain   => [ 'string', '' ],
        selector => 'Handle',
        binds    => {
            User   => 'LOGIN',
            Domain => 'DOMAIN'
        })
    ) {
        next if !defined($user->{LOGIN}) || $seen->{$user->{LOGIN}}++;
        push @users, $user;
    }
    return @users;
}

# -----------------------------------------------------------------
# Get last logged user (Win32_ComputerSystem + Registry fallback)
# -----------------------------------------------------------------
sub _getLastUser {
    my %params = @_;
    my ($system) = getWMIObjects(
        class      => 'Win32_ComputerSystem',
        properties => [ qw/Name UserName/ ],
        %params
    );

    if ($system && $system->{Name} && $system->{UserName}) {
        my $user = {
            DOMAIN => $system->{UserName},
            LOGIN  => $system->{Name}
        };

        if ($user->{DOMAIN} =~ /^([^\\]*)\\(.*)$/) {
            $user->{DOMAIN} = $1 unless $1 eq '.';
            $user->{LOGIN}  = $2;

            if ($user->{DOMAIN} && $user->{DOMAIN} eq 'AzureAD') {
                my $upn = _getLastLoggedAzureADUserUPN(name => $user->{LOGIN}, %params);
                if ($upn && $upn =~ /^([^@]+)\@(.+)$/) {
                    $user->{_fullname} = $user->{LOGIN} . '@AzureAD';
                    $user->{LOGIN}     = $1;
                    $user->{DOMAIN}    = $2;
                }
            }
        }
        return $user;
    }

    my $user;
    return unless any {
        $user = getRegistryValue(path => "HKEY_LOCAL_MACHINE/$_", %params)
    } (
        'SOFTWARE/Microsoft/Windows/CurrentVersion/Authentication/LogonUI/LastLoggedOnSAMUser',
        'SOFTWARE/Microsoft/Windows/CurrentVersion/Authentication/LogonUI/LastLoggedOnUser',
        'SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon/DefaultUserName',
        'SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon/LastUsedUsername'
    );

    if ($user =~ /^([^\\]*)\\(.*)$/) {
        $user = {
            DOMAIN => $1,
            LOGIN  => $2
        };

        $user->{DOMAIN} = $system->{Name}
            if $user->{DOMAIN} eq '.' && $system && $system->{Name};

        if ($user->{DOMAIN} eq '.') {
            my ($useraccount) = getUsers(login => $user->{LOGIN}, %params);
            $user->{DOMAIN} = $useraccount->{DOMAIN} if $useraccount;
        }
        elsif ($user->{DOMAIN} eq 'AzureAD') {
            my $upn = _getLastLoggedAzureADUserUPN(name => $user->{LOGIN}, %params);
            if ($upn && $upn =~ /^([^@]+)\@(.+)$/) {
                $user->{_fullname} = $user->{LOGIN} . '@AzureAD';
                $user->{LOGIN}     = $1;
                $user->{DOMAIN}    = $2;
            }
        }
    }
    return $user;
}

# -----------------------------------------------------------------
# AzureAD: Resolve UPN from SID
# -----------------------------------------------------------------
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

1;