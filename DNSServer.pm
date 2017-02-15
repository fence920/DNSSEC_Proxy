package Net::DNSServer;

use strict;
use Exporter;
use Net::DNS;
use Net::DNS::Packet;
use Net::DNS::RR;
use Net::DNS::Question;
use Net::DNS::SEC::Validator;
use Net::Server::MultiType;
use Fcntl;
use GDBM_File;
use Time::HiRes qw(usleep ualarm gettimeofday tv_interval);
use Getopt::Long qw(GetOptions);
use Carp qw(croak);
use vars qw(@ISA $VERSION);
use warnings ;
@ISA = qw(Exporter Net::Server::MultiType);
$VERSION = '0.11';


sub cache_insert {
  my $packet = shift;
  my ($sec,$min,$hour,$mday,$mon,$year) = localtime(time+5);
  $year += 1900;
  $mon += 1;
  my $ttl = $year.$mon.$mday.$hour.$min.$sec;
  # print STDERR "TTL=".$ttl. "\n";
  my @question = $packet->question;
  my $name = $question[0] -> qname . $question[0] -> qclass . $question[0] -> qtype;
  my $cache = $ttl . "@";
  $cache = join("", ($cache, $packet->header->qr));
  $cache = join(" ", ($cache, $packet->header->aa));
  $cache = join(" ", ($cache, $packet->header->tc));
  $cache = join(" ", ($cache, $packet->header->rd));
  $cache = join(" ", ($cache, $packet->header->opcode));
  $cache = join(" ", ($cache, $packet->header->ra));
  $cache = join(" ", ($cache, $packet->header->z));
  $cache = join(" ", ($cache, $packet->header->ad));
  $cache = join(" ", ($cache, $packet->header->cd));
  $cache = join(" ", ($cache, $packet->header->rcode));
  $cache = join(" ", ($cache, $packet->header->do));
  my @answer = $packet->answer;
  print STDERR "cache answer packet\n", $packet->string, "\n";
  foreach my $ans (@answer){
    $cache = join("!", ($cache, $ans->name));
    $cache = join(" ", ($cache, $ans->type));
    $cache = join(" ", ($cache, $ans->class));
    $cache = join(" ", ($cache, $ans->ttl));
    if ($ans->type eq "CNAME") {
       $cache = join(" ", ($cache, $ans->cname));
    } elsif ($ans->type eq "NS") {
       $cache = join(" ", ($cache, $ans->nsdname));
    } elsif ($ans->type eq "SOA") {
       $cache = join(" ", ($cache, $ans->mname));
       $cache = join(" ", ($cache, $ans->rname));
       $cache = join(" ", ($cache, $ans->serial));
       $cache = join(" ", ($cache, $ans->refresh));
       $cache = join(" ", ($cache, $ans->retry));
       $cache = join(" ", ($cache, $ans->expire));
       $cache = join(" ", ($cache, $ans->minimum));
    } else {
       $cache = join(" ", ($cache, $ans->address));
    }
  }

  # print STDERR "$cache\n";
  my $file = "cache";
  unlink "$file.gdbm" if -e "$file.gdbm";
  tie %Net::DNSServer::db, 'GDBM_File' , "$file.gdbm", O_RDWR|O_CREAT, 0666 or die;
  $Net::DNSServer::db{$name} = $cache;
  untie %Net::DNSServer::db;
  return "キャッシュ成功\n";
}

sub cache_select {
  my $packet = shift;
  my ($sec,$min,$hour,$mday,$mon,$year) = localtime(time);
  $year += 1900;
  $mon += 1;
  my $ttl = $year.$mon.$mday.$hour.$min.$sec;
  print STDERR "DEBUG: Cache Question Packet:\n",$packet->string;
  my $cache_answer_packet = new Net::DNS::Packet( \$packet->data );
  my @question = $packet->question;
  my $name = $question[0] -> qname . $question[0] -> qclass . $question[0] -> qtype;
  my $file = "cache";
  my @str1;
  my @str0;
  tie %Net::DNSServer::db, 'GDBM_File', "$file.gdbm", O_RDONLY, 0644 or die;
  if (defined($Net::DNSServer::db{$name})) {
    @str0 = split(/@/, $Net::DNSServer::db{$name});
    @str1 = split(/!/, $str0[1]);
    if($str0[0] < $ttl) {
       delete $Net::DNSServer::db{$name};
       print STDERR "キャッシュ[" . $name . "]を削除\n";
       print STDERR "キャッシュなし\n";
       return undef;
    }
  }
  else {
    print STDERR "キャッシュなし\n";
    return undef;
  }
  print STDERR "キャッシュあり\n";
  my @head = split(/ /, $str1[0]);
  shift(@str1);
  print STDERR "DEBUG: Cache Question Packet:\n", $cache_answer_packet->string;
  $cache_answer_packet->header->qr($head[0]);
  $cache_answer_packet->header->aa($head[1]);
  $cache_answer_packet->header->tc($head[2]);
  $cache_answer_packet->header->rd($head[3]);
  $cache_answer_packet->header->opcode($head[4]);
  $cache_answer_packet->header->ra($head[5]);
  $cache_answer_packet->header->z($head[6]);
  $cache_answer_packet->header->ad($head[7]);
  $cache_answer_packet->header->cd($head[8]);
  $cache_answer_packet->header->rcode($head[9]);
  $cache_answer_packet->header->do($head[10]);
  foreach my $answer1 (@str1) {
    my $rr;
    my @answer2 = split(/ /, $answer1);
    if ($answer2[1] eq "CNAME") {
       $rr = new Net::DNS::RR(
         name => $answer2[0],
         type => $answer2[1],
         class => $answer2[2],
         ttl => $answer2[3],
         cname => $answer2[4]
       );
    } elsif ($answer2[1] eq "NS") {
       $rr = new Net::DNS::RR(
         name => $answer2[0],
         type => $answer2[1],
         class => $answer2[2],
         ttl => $answer2[3],
         nsdname => $answer2[4]
       );
    } elsif ($answer2[1] eq "SOA") {
       $rr = new Net::DNS::RR(
         name => $answer2[0],
         type => $answer2[1],
         class => $answer2[2],
         ttl => $answer2[3],
         mname => $answer2[4],
         rname => $answer2[5],
         serial => $answer2[6],
         refresh => $answer2[7],
         retry => $answer2[8],
         expire => $answer2[9],
         minimum => $answer2[10]
       );
    } else {
       $rr = new Net::DNS::RR(
         name => $answer2[0],
         type => $answer2[1],
         class => $answer2[2],
         ttl => $answer2[3],
         address => $answer2[4]
       );
    }
    $cache_answer_packet->push(pre => $rr);
  }
  untie %Net::DNSServer::db;
  print STDERR "cache answer\n";
  print STDERR $cache_answer_packet->string;
  return $cache_answer_packet;
}

sub run {
  my $file = "cache";
  unlink "$file.gdbm" if -e "$file.gdbm";
  tie %Net::DNSServer::db, 'GDBM_File' , "$file.gdbm", O_RDWR|O_CREAT, 0666 or die;
  untie %Net::DNSServer::db;
  
  my $class = shift;
  $class = ref $class || $class;
  my $prop  = shift;
  unless ($prop &&
          (ref $prop) &&
          (ref $prop eq "HASH") &&
          ($prop->{priority}) &&
          (ref $prop->{priority} eq "ARRAY")) {
    croak "Usage> $class->run({priority => \\\@resolvers})";
  }
  foreach (@{ $prop->{priority} }) {
    my $type = ref $_;
    if (!$type) {
      croak "Not a Net::DNSServer::Base object [$_]";
    } elsif (!$_->isa('Net::DNSServer::Base')) {
      croak "Resolver object must isa Net::DNSServer::Base (Type [$type] is not?)";
    }
  }
  my $self = bless $prop, $class;

  $self->{server}->{commandline} ||= [ $0, @ARGV ];
  # Fix up process title on a "ps"
  $0 = join(" ",$0,@ARGV);

  my ($help,$conf_file,$nodaemon,$user,$group,$server_port,$pidfile);
  GetOptions     # arguments compatible with bind8
    ("help"       => \$help,
     "config-file|boot-file=s" => \$conf_file,
     "foreground" => \$nodaemon,
     "user=s"     => \$user,
     "group=s"    => \$group,
     "port=s"     => \$server_port,
     "Pidfile=s"  => \$pidfile,
     ) or $self -> help();
  $self -> help() if $help;

  # Load general configuration settings
  $conf_file ||= "/etc/named.conf";
  ### XXX - FIXME: not working yet...
  # $self -> load_configuration($conf_file);

  # Daemonize into the background
  $self -> {server} -> {setsid} = 1 unless $nodaemon;

  # Effective uid
  $self -> {server} -> {user} = $user if defined $user;

  # Effective gid
  $self -> {server} -> {group} = $group if defined $group;

  # Which port to bind
  # $server_port ||= getservbyname("domain", "udp") || 53;
  $server_port ||= 9053;
  $self -> {server} -> {port} = ["$server_port/tcp", "$server_port/udp"];

  # Where to store process ID for parent process
  $self -> {server} -> {pid_file} ||= $pidfile || "/tmp/named.pid";

  # Listen queue length
  $self -> {server} -> {listen} ||= 12;

  # Default IP to bind to
  $self -> {server} -> {host} ||= "0.0.0.0";

  # Show warnings until configuration has been initialized
  $self -> {server} -> {log_level} ||= 1;

  # Where to send errors
  $self -> {server} -> {log_file} ||= "/tmp/rob-named.error_log";

  return $self->SUPER::run(@_);
}

sub help {
  my ($p)=$0=~m%([^/]+)$%;
  print "Usage> $p [ -u <user> ] [ -f ] [ -(b|c) config_file ] [ -p port# ] [ -P pidfile ]\n";
  exit 1;
}

sub post_configure_hook {
  my $self = shift;
  open (STDERR, ">>$self->{server}->{log_file}");
  local $_;
  foreach (@{$self -> {priority}}) {
    $_->init($self);
  }
}

sub pre_server_close_hook {
  my $self = shift;
  local $_;
  # Call cleanup() routines
  foreach (@{$self -> {priority}}) {
    $_->cleanup($self);
  }
}

sub restart_close_hook {
  my $self = shift;
  local $_;
  # Call cleanup() routines
  foreach (@{$self -> {priority}}) {
    $_->cleanup($self);
  }
  # Make sure everything is taint clean ready before exec
  foreach (@{ $self->{server}->{commandline} }) {
    # Taintify commandline
    $_ = $1 if /^(.*)$/;
  }
  foreach (keys %ENV) {
    # Taintify %ENV
    $ENV{$_} = $1 if $ENV{$_} =~ /^(.*)$/;
  }
}

my $vflag = 0;
my $tflag = 0;
my $str1;
my $str2;
my $alarmTime;

sub process_request {
  my $self = shift;
  my $peeraddr = $self -> {server} -> {peeraddr};
  my $peerport = $self -> {server} -> {peerport};
  my $sockaddr = $self -> {server} -> {sockaddr};
  my $sockport = $self -> {server} -> {sockport};
  my $proto    = $self -> {server} -> {udp_true} ? "udp" : "tcp";
  print STDERR "DEBUG: process_request from [$peeraddr:$peerport] for [$sockaddr:$sockport] on [$proto] ...\n";
  local $0 = "named: $peeraddr:$peerport";
  if( $self -> {server} -> {udp_true} ){
    print STDERR "DEBUG: udp packet received!\n";
    my $dns_packet = new Net::DNS::Packet (\$self -> {server} -> {udp_data});
    print STDERR "DEBUG: Question Packet:\n",$dns_packet->string;
    my $cache_answer = undef;
    $cache_answer = cache_select($dns_packet);
    if (defined($cache_answer)) {
        print STDERR "キャッシュからの取り出し成功\n";
        print STDERR $cache_answer->string;
        $self -> {server} -> {client} -> send($cache_answer->data);
        print STDERR "DEBUG: Answer Packet:\n",$cache_answer->string;
        return;
    } else {
        print STDERR "キャッシュからの取り出し失敗\n";
    }
    if($dns_packet->header->cd == 1) {
        foreach (@{$self -> {priority}}) {
          $_->pre($dns_packet);
        }
        my $answer_packet = undef;
        print STDERR "DEBUG: Preparing for resolvers...\n";
        foreach (@{$self -> {priority}}) {
          print STDERR "DEBUG: Executing ",(ref $_),"->resolve() ...\n";
          $answer_packet = $_->resolve2();
          last if $answer_packet;
        }
        $self -> {answer_packet} = $answer_packet || $dns_packet;
        $self -> {server} -> {client} -> send($self->{answer_packet}->data);
        # print STDERR cache_insert($self -> {answer_packet});
    }
    else {
      eval {
          local $SIG{ALRM} = sub { die "timeout" };

          # Call pre() routine for each module
          foreach (@{$self -> {priority}}) {
            $_->pre($dns_packet);
          }

          my $t0 = [gettimeofday]; #時間計測開始

          # Keep calling resolve() routine until one module resolves it
          my $answer_packet = undef;
          print STDERR "DEBUG: Preparing for resolvers...\n";
          foreach (@{$self -> {priority}}) {
            print STDERR "DEBUG: Executing ",(ref $_),"->resolve() ...\n";
            $answer_packet = $_->resolve2();
            last if $answer_packet;
          }

          my $t1 = [gettimeofday]; #時間計測終了
          my $execTime = tv_interval($t0, $t1); #最初の名前解決にかかった時間

          if($execTime > 1.95) {
            $alarmTime = 10000000;
            print STDERR "exec時間[". $execTime ."]\n";
          } else {
            $alarmTime = 1950000 - ($execTime*1000000);
            print STDERR "exec時間[". $execTime ."]\n";
          }

          ualarm $alarmTime;

          # For DEBUGGING purposes, use the question as the answer
          # if no module could figure out the real answer (echo)
          $self -> {answer_packet} = $answer_packet || $dns_packet;

          my $space = "  ";
	   my @question = $self->{answer_packet} -> question;
	   my $qname = $question[0] -> qname; #応答パケットから問い合わせたドメイン名を取り出す
	   my $qclass = $question[0]->class;  #応答パケットから問い合わせたクラスを取り出す
	   my $qtype = $question[0] -> type;  #応答パケットから問い合わせたタイプを取り出す

           # 検証失敗時のポップアップを表示させるためのコマンド
	   $str1 = "dnssec_untrust_v1.01.exe " . $qname . $space . $qclass . $space . $qtype;
	   # タイムアウト時のポップアップを表示させるためのコマンド
	   $str2 = "timeout_popup.exe " . $qname . $space . $qclass . $space . $qtype;

	   $Net::DNSServer::val1 = new Net::DNS::SEC::Validator(
	      # nslist => "8.8.8.8",
	      nslist => '[127.0.0.1]:10053',
              # nslist => '[127.0.0.1]:5353',
	      rec_fallback => 0,
	      log_target => "7:stderr",
	      policy => ":"
	   );

	   my $a = $Net::DNSServer::val1->resolve_and_check($qname, $qclass, $qtype, VAL_QUERY_AC_DETAIL); #DNSSECの検証
	   my $status = 0;
	   my $c1 = 0;
	   my @status2;
	   # print STDERR "DEBUG: \n" , $self->{answer_packet}->header->string ;
	   foreach my $i (@$a) {
	     if($c1 == 0) {
	        $status = ${$i}{status};
	     }
	     $status2[$c1]=${$i}{status};
	     $c1 += 1;
	     # print STDERR "Status: " .  $val1->valStatusStr(${$i}{status}) . "(" . ${$i}{status} . ")\n";
	   }
	   if($status == 128 || $status == 133 || $status == 134){
	     foreach my $j (@status2) {
	       if($j != 128 || $j != 133 || $j != 134){
	         $status = $j;
	         last;
	       }
	     }
	   }
	   if($status == 4 || $status == 1 || $status == 3) { #StatusがVAL_NOTRUST(4)またはVAL_BOGUS(1)またはVAL_INDETERMINATE(3)のとき
	     $dns_packet->header->qr(1);
	     $dns_packet->header->ra(1);
	     $dns_packet->header->cd(0);
	     $dns_packet->header->ad(0);
	     for(my $c3 =  $dns_packet->header->ancount; $c3 >= 0; $c3 -= 1) { #AnswerセクションのRRを削除
	       $dns_packet->pop( 'pre' );
	     }

	     foreach my $h (@$a) { #AnswerセクションにRRを追加
	       my $acs = ${$h}{answer};
	       foreach my $ac (@$acs) {
	         print "AC status: " . ${$ac}{status} . "\n";
	         my $acr = ${$ac}{rrset};
	         my $acd = ${$acr}{data};
	         foreach my $d (@$acd) {
	           $dns_packet->push(pre => ${$d}{rrdata});
	         }
	         $acs = ${$acr}{sigs};
	         foreach my $d (@$acs) {
	           if($self->{answer_packet}->header->do == 1){ 
	             $dns_packet->push(pre => ${$d}{rrdata});
	           }
	         }
	         last;
	       }
	       $c1 -= 1;
	       last if($c1 == 0);
	     }
	     # Before the answer is sent to the client
	     # Run it through the post() routine for each module
	     foreach (@{$self -> {priority}}) {
	       $_->post( $dns_packet );
	     }
	     $self -> {server} -> {client} -> send($dns_packet->data);

	     print STDERR cache_insert($dns_packet);

	     $vflag = 1;

	   } elsif($status == 128 || $status == 133 || $status == 134) { #検証に成功したとき
	     $self->{answer_packet}->header->ad(1);
	     $self->{answer_packet}->header->cd(0);
	     $self->{answer_packet}->header->qr(1);
	     $self->{answer_packet}->header->ra(1);
	     $self->{answer_packet}->header->rd(1);
	     for(my $c2 =  $self->{answer_packet}->header->ancount; $c2 >= 0; $c2 -= 1) { #AnswerセクションのRRを削除
	       $self->{answer_packet}->pop( 'pre' );
	     }
	     foreach my $h (@$a) { #AnswerセクションにRRを追加
	       my $acs = ${$h}{answer};
	       foreach my $ac (@$acs) {
	         print "AC status: " . ${$ac}{status} . "\n";
	         my $acr = ${$ac}{rrset};
	         my $acd = ${$acr}{data};
	         foreach my $d (@$acd) {
	           $self->{answer_packet}->push(pre => ${$d}{rrdata});
	         }
	         $acs = ${$acr}{sigs};
	         foreach my $d (@$acs) {
	           if($self->{answer_packet}->header->do == 1){ 
	             $self->{answer_packet}->push(pre => ${$d}{rrdata});
	           }
	         }
	         last;
	       }
	       $c1 -= 1;
	       last if($c1 == 0);
	     }
	     foreach (@{$self -> {priority}}) {
	       $_->post( $self -> {answer_packet} );
	     }
	              
	     $self -> {server} -> {client} -> send($self->{answer_packet}->data);

	     print STDERR cache_insert($self->{answer_packet});

	     print STDERR "DEBUG: Answer Packet :\n",$self->{answer_packet}->string;

	   } else { #Statusが上記以外のとき
	     foreach (@{$self -> {priority}}) {
	       $_->post( $self -> {answer_packet} );
	     }
	     $self->{answer_packet}->header->cd(0);
	     $self->{answer_packet}->header->qr(1);
	     $self->{answer_packet}->header->ra(1);
	     $self->{answer_packet}->header->rd(1);
	     $self -> {server} -> {client} -> send($self->{answer_packet}->data);

	     print STDERR cache_insert($self->{answer_packet});

	   }

          ualarm 0;
      };
      ualarm 0;
      if($@) {
         if($@ =~ /timeout/) {
           # タイムアウト時の処理
           $self -> {server} -> {client} -> send($self->{answer_packet}->data);
           $tflag = 1;
           # $vflag = 0;
           print STDERR "タイムアウト"."\n";
         }
      }
      print STDERR "alarm時間[". $alarmTime ."]\n";
      if($tflag == 1 ) {
         system($str2);
      } elsif($tflag == 0 && $vflag == 1) {
         system($str1);
      }

    }
  } else {
    print STDERR "DEBUG: Incoming TCP packet? Not implemented\n";
  }
}


1;
__END__

=head1 NAME

Net::DNSServer - Perl module to be used as a name server

=head1 SYNOPSIS

  use Net::DNSServer;

  run Net::DNSServer {
    priority => [ list of resolver objects ],
  };
  # never returns

=head1 DESCRIPTION

Net::DNSServer will run a name server based on the
Net::DNSServer::Base resolver objects passed to it.
Usually the first resolver is some sort of caching
resolver.  The rest depend on what kind of name
server you are trying to run.  The run() method
never returns.

=head1 AUTHOR

Rob Brown, rob@roobik.com

=head1 SEE ALSO

L<Net::DNSServer::Base>,
L<Net::DNS>,
L<Net::Server>

named(8).

=head1 COPYRIGHT

Copyright (c) 2001, Rob Brown.  All rights reserved.
Net::DNSServer is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

$Id: DNSServer.pm,v 1.25 2002/11/13 19:47:01 rob Exp $

=cut
