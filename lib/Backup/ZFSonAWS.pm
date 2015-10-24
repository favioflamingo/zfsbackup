package Backup::ZFSonAWS;

use 5.006;
use strict;
use warnings FATAL => 'all';
use IO::Handle;
use Data::Dumper;
use Crypt::CBC;
use Digest::SHA qw(sha256_hex);
use JSON::XS;
use Date::Calc;

=head1 NAME

Backup::ZFSonAWS - The great new Backup::ZFSonAWS!

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.1';


=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use Backup::ZFSonAWS;

    my $foo = Backup::ZFSonAWS->new();
    ...

=head1 EXPORT

A list of functions that can be exported.  You can delete this section
if you don't export anything, such as for a purely object-oriented module.

=head1 SUBROUTINES/METHODS

=head2 function1

=cut

=pod

---+ /usr/local/bin/zfsbackup putemailofgpgkeyhere@example.com

Usage: zfsbackup bucketname 

This command assumes that there is a place for temporary file storage called "/var/backup", which is the mountpoint for a filesystem that does not get backed up.


Backup::ZFSonAWS->new({
	'bucket' => 's3zfsbucket',
	'tmppath' => '/var/backup',
	'tmpfs' => 'tank/backup',
	'recipient' => 'favio@example.com'
});

=cut


sub new {
	my $package = shift;
	my $options = shift;
	my $this = {};
	bless($this,$package);
	#### check inputs
	# bucket
	if(defined $options->{'bucket'} && $options->{'bucket'} =~ m/^([0-9a-zA-Z\-]+)$/){
		$this->{'bucket'} = $1;
	}
	else{
		die "no bucket";
	}
	if(defined $options->{'tmppath'} && $options->{'tmppath'} =~ m/^(.*)$/){
		$this->{'tmppath'} = $1;
	}
	else{
		die "bad format for tmppath";
	}
	unless(-d $this->{'tmppath'}){
		die "directory does not exist for tmppath";
	}
	if(defined $options->{'tmpfs'} && $options->{'tmpfs'} =~ m/^(.*)$/){
		$this->{'tmpfs'} = $1;
	}
	else{
		die "no zfs file system to store images";
	}
	
	if(defined $options->{'recipient'} && $options->{'recipient'} =~ m/^(.*)$/){
		$this->{'recipient'} = $1;
	}
	else{
		die "no gpg recipient provided";
	}
	
	return $this;
}


=pod

---+ Getters/Setters

=cut

sub bucket {
	return shift->{'bucket'};
}

sub tmpfs {
	return shift->{'tmpfs'};
}

sub tmppath {
	return shift->{'tmppath'};
}

sub recipient {
	return shift->{'recipient'};
}


sub add_pid {
	my $this = shift;
	my $pid = shift;
	if( defined $pid && $pid =~ m/^(\d+)$/){
		$pid = $1;
	}
	unless(defined $this->{'children'}){
		$this->{'children'} = [];
	}
	push(@{$this->{'children'}},$pid);

	return scalar(@{$this->{'children'}});
}



=pod

---+ Main Subroutines


=cut

=pod

--++ wait_for_children()

When it is time to kill this object, we need to wait for all child processes to exit.

=cut

sub wait_for_children{
	use POSIX;
	my $this = shift;
	
	unless(defined $this->{'children'}){
		$this->{'children'} = [];
	}
	
	
	my @still_going;
	while(scalar(@{$this->{'children'}}) > 0){
		my $latestpid = shift(@{$this->{'children'}});
		warn "Waiting for $latestpid to exit";
		
		my $reaped = waitpid $latestpid => WNOHANG;
		if ($reaped == $latestpid) {
			warn "$latestpid is already gone.\n";
		} else {
			warn "$latestpid is still running.\n";
			push(@still_going,$latestpid);
		}
	}
	$this->{'children'} = \@still_going;
	
}


=pod

---++ extract_zfs_snapshots

Run zfs list -t snapshot and get a list of all the snapshots.

=cut

sub extract_zfs_snapshots {
	my $this = shift;
	my $varbackup = $this->tmpfs;
	my $pid = open(my $fh, "-|", '/sbin/zfs','list','-t','snapshot') || die "cannot extract zfs stuff";
	my $data = {};
	while(my $line = <$fh>){
#		chomp($line);
#		print "LINE=$line\n";
		if($line =~ m/(.*)\@(\d{4})(\d{2})(\d{2})[\t\s]/){
			#print "match=$1\n";
			my @x = ($2,$3,$4);
			my $zfspath = $1;
			next if $zfspath eq $varbackup;
			$zfspath =~ s/\//_/g;
			$data->{$zfspath} = [] unless defined $data->{$zfspath};
			push(@{$data->{$zfspath}},\@x);
		}
	}
	return $data;
}

sub extract_aws_content {
	my $this = shift;
	
	my $pid = open(my $fh,"-|",'/usr/local/bin/aws','s3','ls','s3://'.$this->bucket) || die "cannot extract aws stuff";
	my $data = {'incremental' => {},'full' => {}};
	my $previous = [];
	while(my $line = <$fh>){
		# 2014-10-28 04:19:11   10486784 scooper-wiki_20141019D_964783120
		if($line =~ m/incrementalzfsbackup(.*)_(\d{4})(\d{2})(\d{2})_(\d{4})(\d{2})(\d{2})/){
			#$data->{'incremental'}->{$1} = [] unless defined $data->{$1};
			#push(@{$data->{'incremental'}->{$1}},[$2,$3,$4,$5,$6,$7]);
			$data->{'incremental'}->{$1}->{$2.$3.$4}->{$5.$6.$7} = 1;
		}
		elsif($line =~ m/fullzfsbackup(.*)_(\d{4})(\d{2})(\d{2})/){
			#$data->{'full'}->{$1} = {} unless defined $data->{$1};
			#push(@{$data->{'full'}->{$1}},[$2,$3,$4]);
			$data->{'full'}->{$1}->{$2.$3.$4} = 1;
		}
	}
	return $data;
}

sub encrypt_txt {
	my $this = shift;
	my $path = shift;
	my $txt = shift;
	# /usr/bin/gpg -r dejesus.joel@e-flamingo.jp --armor -o - -e -
	open(my $fh, "|-",'/usr/bin/gpg','--batch','--yes','-r',$this->recipient,'--armor','-o',$path,'-e','-') || die "cannot do gpg";
	syswrite($fh,$txt);
	close($fh);
}

=pod

---++ generate_random_key(32)

In bytes, say how many random bytes you want from /dev/random

=cut

sub generate_random_key {
	my $this = shift;
	my $total = shift;
	$total ||= 32;
	open(my $fh,'<','/dev/random') || die "cannot read from /dev/random";
	my $i = 0;
	my $buf = '';
	my $num = '';
	while($i<$total){
		$i += sysread($fh,$buf,$total-$i);
		$num .= $buf;
	}
	close($fh);
	# untaint
	if($num =~ m/^(.*)$/){
		$num = $1;
	}
	return $num;
}

=pod

---++ get_symmetric_cipher

The cipher is from Crypt::OpenSSL::AES which is a magnitude faster than pure perl implementations.

=cut

sub get_symmetric_cipher{
	my $this = shift;
	
	my $key = shift;
	return Crypt::CBC->new(-key => $key, -cipher => 'Crypt::OpenSSL::AES');
}

=pod

---++ cp_to_aws($filepath,$s3path)

Copy files from the local disk to your Amazon S3 bucket.  This subroutine utilitzes the aws cli program.

=cut

sub cp_to_aws{
	my $this = shift;
	
	my ($fpath,$s3path) = (shift,shift);
	
	die "file does not exist" unless -f $fpath;
	
	
	my $pid = fork();
	if($pid > 0){
		print STDERR "Forking with pid=$pid to copy $fpath to aws at address s3://".$this->bucket."/$s3path\n";
		$this->add_pid($pid);
	}
	elsif($pid == 0){
		# child
		system('/usr/local/bin/aws','s3','cp',$fpath,'s3://'.$this->bucket.'/'.$s3path);
		system('/bin/rm','-v',$fpath);
		exit(0);
	}
	else{
		die "cannot fork to do aws cp";
	}
	
}

=pod

---++ compress_zfs_send($sendpath,$relpath)

Compress zfs with bzip2 -c

Return a file handle, on which a checksum and encryption operation is to take place.

This implements the equivalent bash command: zfs send tank/example | bzip2 -c, and returns a file handle which reads the stdout from the bzip2 process.

=cut

sub compress_zfs_send {
	my $this = shift;
	my $sendpath = shift;
	my $relpath = shift;
	
	if(defined $relpath){
		print STDERR "Running zfs send -i $relpath $sendpath\n";
	}
	else{
		print STDERR "Running zfs send $sendpath\n";
	}
	
	
	my ($fhzfsout,$fhbzipin,$fhbzipout,$fhreturn);
	pipe($fhbzipin,$fhzfsout);
	pipe($fhreturn,$fhbzipout);

	my $sendpid = fork();
	if($sendpid > 0){
		# parent
		$this->add_pid($sendpid);
	}
	elsif($sendpid == 0){
		close($fhbzipin);
		close($fhbzipout);
		close($fhreturn);
		
		# child, stdout=$fhzfsout
		open (STDOUT, '>&', $fhzfsout);
		#STDOUT->fdopen( $fhzfsout, 'w' ) or die $!;
		
		if(defined $relpath){
			exec('/sbin/zfs','send','-i',$relpath,$sendpath);
		}
		else{
			exec('/sbin/zfs','send',$sendpath);			
		}
		
		
		exit(1);
	}
	else{
		die "failed to for for bzip2 ";
	}

	my $compresspid = fork();
	if($compresspid > 0){
		# parent
		$this->add_pid($compresspid);
	}
	elsif($compresspid == 0){
		# child
		close($fhzfsout);
		close($fhreturn);	
		# stdin=$fsbzipin, stdout=$fhbzipout
		#open FILE, ">$file";
		open (STDIN, '<&', $fhbzipin);
		open (STDOUT, '>&', $fhbzipout);
		#STDIN->fdopen( $fhbzipin,  'r' ) or die $!;
		#STDOUT->fdopen( $fhbzipout, 'w' ) or die $!;
		exec('/bin/bzip2','-c');
		exit(1);
	}
	else{
		die "failed to for for bzip2 ";
	}
	close($fhbzipin);
	close($fhbzipout);
	close($fhzfsout);
	
	
	return $fhreturn;
}

=pod

---++ decompress_zfs_receive

bzcat

=cut

=pod

---++ backup_full($zfs_filesystem,$date)

$zfs_filesystem is formatted with underscores (_) in place of forward slashes (/);


=cut

sub backup_full {
	my $this = shift;
	
	my ($fs,$date) = (shift,shift);
	
	# check to see if anyone has exited already
	$this->wait_for_children();
	
	
	my $zfspath = $fs;
	$zfspath =~ s/_/\//g;
	print STDERR "zfs backup($zfspath,$date)\n";
	# fullzfsbackup(.*)_(\d{4})(\d{2})(\d{2})
	print STDERR "...s3path=fullzfsbackup".$zfspath."_".$date."\n";
	#encrypt_txt('/tmp/test',generate_random_key(32));
	#open(my $fh, "-|",'/sbin/zfs','send',$zfspath.'@'.$date) || die "cannot do zfs backup";
	my $fh = $this->compress_zfs_send($zfspath.'@'.$date);
	die "bad file handle from compress_zfs_send" unless defined $fh && fileno($fh) > 0;
	
	open(my $fhout,'>',$this->tmppath.'/'.$fs.'_'.$date) || die "cannot write zfs to disk";
	my $i = 0;
	my $buf;
	my $sha = Digest::SHA->new(256);
	my $key = $this->generate_random_key(32);
	my $cipher = $this->get_symmetric_cipher($key);
	$cipher->start('encrypting');
	while($i = sysread($fh,$buf,8192)){
		# encrypt then get checksum
		$buf = $cipher->crypt($buf);
		$sha->add($buf);
		my $x = syswrite($fhout,$buf);
		die "failed to write out" unless $x == length($buf);
	}
	$buf = $cipher->finish();
	$sha->add($buf);
	my $x2 = syswrite($fhout,$buf);
	die "failed to write out" unless $x2 == length($buf);
	close($fhout);
	close($fh);

	my $checksum = $sha->digest();
	print STDERR "Length of check sum for $fs is ".length($checksum)." and key length =".length($key)."\n";
	# format= [4 bytes][checksum][4 bytes][key]
	$this->encrypt_txt($this->tmppath.'/'.$fs.'_'.$date.'.gpg',pack('L',length($checksum )).$checksum.pack('L',length($key )).$key  );
	$this->cp_to_aws($this->tmppath.'/'.$fs.'_'.$date,'fullzfsbackup'.$fs.'_'.$date);
	$this->cp_to_aws($this->tmppath.'/'.$fs.'_'.$date.'.gpg','fullzfsbackup'.$fs.'_'.$date.'.gpg');

}

#incrementalzfsbackup(.*)_(\d{4})(\d{2})(\d{2})_(\d{4})(\d{2})(\d{2})

sub do_full_snapshot {
	my $this = shift;
	my ($snaplocal,$snapaws) = (shift,shift);
	
	
	
	#require Data::Dumper;
	#my $xo = Data::Dumper::Dumper($snaplocal);
	#my $yo = Data::Dumper::Dumper($snapaws);
	#print STDERR "Local=$xo\n---\nAWS=$yo\n";
	#print STDERR "AWS=$yo\n";
	
	# find the first element of all zfs filesystem
	return undef unless defined $snaplocal && ref($snaplocal) eq 'HASH';
	# The format of $fs is tank_sub1_sub2 
	foreach my $fs (keys %{$snaplocal}){
		print STDERR "$fs\n";
		if(defined $snapaws->{'full'}->{$fs} && defined $snapaws->{'full'}->{$fs}->{join('',@{$snaplocal->{$fs}->[0]})}  ){
			print STDERR "...Full defined\n";
			
			# search increments
			# 
			# $snapaws->{'incremental'}->{$fs}->{join('',@{$snaplocal->{$fs}->[0]})}->{}
			foreach my $i (1..(scalar(@{$snaplocal->{$fs}})-1) ){
				next if defined $snapaws->{'incremental'}->{$fs}->{join('',@{$snaplocal->{$fs}->[$i-1]})}
					&& $snapaws->{'incremental'}->{$fs}->{join('',@{$snaplocal->{$fs}->[$i-1]})}->{join('',@{$snaplocal->{$fs}->[$i]})};
				$this->do_incremental_snapshots($fs, join('',@{$snaplocal->{$fs}->[$i-1]}), join('',@{$snaplocal->{$fs}->[$i]})  );
				
				
				system('/sbin/zfs','destroy',$fs.'@'.join('',@{$snaplocal->{$fs}->[$i-1]}));
			}
		}
		else{
			print STDERR "..do full backup\n";
			$this->backup_full($fs,join('',@{$snaplocal->{$fs}->[0]}));
		}
	}
	
	return [$snaplocal,$snapaws];
}



=pod


---++ do_incremental_snapshots($fs,$from,$to)

Basically, run zfs send -R -i $fs@$from $fs@$to

=cut

sub do_incremental_snapshots {
	my $this = shift;
	
	my ($fs,$fromdate,$todate) = (shift,shift,shift);
	
	# check to see if any child processes have exited already
	$this->wait_for_children();
	
	my $zfspath = $fs;
	$zfspath =~ s/_/\//g;
	print STDERR "zfs backup($zfspath,$fromdate,$todate)\n";
	# fullzfsbackup(.*)_(\d{4})(\d{2})(\d{2})
	print STDERR "...s3path=incrementalzfsbackup".$zfspath."_".$fromdate."_".$todate."\n";
	#return undef;
	
	#encrypt_txt('/tmp/test',generate_random_key(32));
	#open(my $fh, "-|",'/sbin/zfs','send',$zfspath.'@'.$date) || die "cannot do zfs backup";
	my $fh = $this->compress_zfs_send($zfspath.'@'.$todate,$zfspath.'@'.$fromdate);
	die "bad file handle from compress_zfs_send" unless defined $fh && fileno($fh) > 0;
	
	open(my $fhout,'>',$this->tmppath.'/'.$fs.'_'.$fromdate.'_'.$todate) || die "cannot write zfs to disk";
	my $i = 0;
	my $buf;
	my $sha = Digest::SHA->new(256);
	my $key = $this->generate_random_key(32);
	my $cipher = $this->get_symmetric_cipher($key);
	$cipher->start('encrypting');
	while($i = sysread($fh,$buf,8192)){
		# encrypt then get checksum
		$buf = $cipher->crypt($buf);
		$sha->add($buf);
		my $x = syswrite($fhout,$buf);
		die "failed to write out" unless $x == length($buf);
	}
	$buf = $cipher->finish();
	$sha->add($buf);
	my $x2 = syswrite($fhout,$buf);
	die "failed to write out" unless $x2 == length($buf);
	close($fhout);
	close($fh);

	my $checksum = $sha->digest();
	print STDERR "Length of check sum for $fs is ".length($checksum)." and key length =".length($key)."\n";
	# format= [4 bytes][checksum][4 bytes][key]
	$this->encrypt_txt($this->tmppath.'/'.$fs.'_'.$fromdate.'_'.$todate.'.gpg',pack('L',length($checksum )).$checksum.pack('L',length($key )).$key  );
	$this->cp_to_aws($this->tmppath.'/'.$fs.'_'.$fromdate.'_'.$todate,'incrementalzfsbackup'.$fs.'_'.$fromdate.'_'.$todate);
	$this->cp_to_aws($this->tmppath.'/'.$fs.'_'.$fromdate.'_'.$todate.'.gpg','incrementalzfsbackup'.$fs.'_'.$fromdate.'_'.$todate.'.gpg');
}


=pod


---+ Command Line Arg Parsing


=cut

sub get_options {
	my @args = @_;
	my $func = shift(@args);
	die "no function defined" unless defined $func;
	if($func eq 'recover'){
		return get_options_recover(@args);
	}
	elsif($func eq 'backup'){
		return get_options_backup(@args);
	}
	elsif($func eq 'reset'){
		return get_options_reset(@args);
	}
	else{
		die "bad options";
	}
}

sub read_config_file {
	my $path = '/etc/zfsbackup/backup.conf';
	die " no conf file exists" unless -f $path;
	open(my $fh, '<',$path) || die "cannot open file";
	my $x = '';
	while(<$fh>){ $x .= $_;}
	close($fh);
	
	return JSON::XS::decode_json($x);	
}


sub get_options_backup {
	my @args = @_;
	my $data = read_config_file(); 
	$data->{'function'} = 'backup';
	# read conf file
	return $data;
}

sub get_options_reset{
	my @args = @_;
	my $data = read_config_file(); 
	$data->{'function'} = 'reset';
	# read conf file
	return $data;
}


sub get_options_recover {
	my @args = @_;
	my $data = read_config_file();
	die " no clear text key and checksum file" unless defined $args[0] && -f $args[0];
	if($args[0] =~ m/^(.*)$/){
		$data->{'checksumfile'} = $args[0];
	}
	die " no cipher text zfs snapshot" unless defined $args[1] && -f $args[1];
	if($args[1] =~ m/^(.*)$/){
		$data->{'snapshotfile'} = $args[1];
	}
	$data->{'function'} = 'recover';
	return $data;
}


sub run_backup {
	my $this = shift;
	
	#my $xo = Data::Dumper::Dumper($this->extract_zfs_snapshots());
	#my $yo = Data::Dumper::Dumper($this->extract_aws_content());
	#die "XO=$xo\n\nYO=$yo";
	
	
	# find out new full snapshots to take, and run the full snapshot backup
	my $required_incremental = $this->do_full_snapshot(
		$this->extract_zfs_snapshots(),
		$this->extract_aws_content()
	);


	# find out new incremental snaphosts


	# find out what snapshots to delete

}

=pod

---+ Reset

Start a new series of backups, whereby the full snapshot is set for today.

   1. Delete all snapshots.
   
   
 {
          'storage-space_kvm-virts_tor01' => [
                                               [
                                                 '2015',
                                                 '10',
                                                 '02'
                                               ],
 
 
 
=cut

sub reset_snapshots {
	my $this = shift;
	
	my $ref = $this->extract_zfs_snapshots();

	die "could not find any snapshots used in backups\n" unless 
		defined $ref && ref($ref) eq 'HASH';
	
	foreach my $fs (sort keys %{$ref}){
		print STDERR "Resetting $fs\n";
		next unless defined $ref->{$fs} && ref($ref->{$fs}) eq 'ARRAY';
		
		foreach my $i (0..(scalar(@{$ref->{$fs}})-1)  ){
			$this->wait_for_children();
			
			next unless
				defined $ref->{$fs}->[$i] && ref($ref->{$fs}->[$i]) eq 'ARRAY' && scalar(@{$ref->{$fs}->[$i]}) == 3;
			
			print STDERR "Deleting snapshot ".$fs.'@'.join('',@{$ref->{$fs}->[$i]})."\n";
			
			$this->delete_snapshot($fs,join('',@{$ref->{$fs}->[$i]})   );
			
			sleep 3;
		}
		
		
	}
	
}

=pod

---++ delete_snapshot($fs,$date)

Delete the zfs snapshot.

=cut

sub delete_snapshot {
	my $this = shift;
	my $fs = shift;
	my $date = shift;
	
	die "bad format for file system" unless defined $fs && $fs =~ m/^([0-9a-zA-Z\_\-]+)$/;
	die "bad format for date" unless defined $date && $date =~ m/^(\d+)$/;
	
	$fs =~ s/_/\//g;
	
	my $pid = fork();
	
	if($pid > 0){
		# parent
		$this->add_pid($pid);
	}
	elsif($pid == 0){
		# child
		exec('/sbin/zfs','destroy',$fs.'@'.$date);
		exit(1);
	}
	else{
		die "could not fork to do exec";
	}
	
}


=pod

---+ Recovery

=cut


sub extract_key_checksum {
	my $this = shift;
	my $filepath = shift;
	open(my $fh, '<', $filepath ) || die "cannot open cleartext file";
	my $x = '';
	my $buf;
	my $n = 0;
	my $size = 0;
	$n = read($fh,$buf,4);
	$size = unpack('L',$buf);
	$n = read($fh,$buf,$size);
	die "bad size" unless $n == $size;
	my $checksum = $buf;
	
	$n = read($fh,$buf,4);
	$size = unpack('L',$buf);
	$n = read($fh,$buf,$size);
	die "bad size" unless $n == $size;
	my $key = $buf;
	
	close($fh);
	return ($checksum,$key);
}

=pod

---++ decrypt_snapshot

Take a snapshot, decrypt it and print it to stdout.

zfsonaws recover /tmp/checksumfile /tmp/fullzfsbackup_tank_example_20150101_20150110 | zfs recevie tank/example

=cut 

sub decrypt_snapshot{
	my $this = shift;
	my $checksumfile_path = shift;
	my $snapshotfile_path = shift;
	die "checksum file path does not exist" unless -f $checksumfile_path;
	die "snapshot file path does not exist" unless -f $snapshotfile_path;
	
	my ($checksum,$key) = $this->extract_key_checksum($checksumfile_path);
	return $this->decrypt_snapshot_alpha($snapshotfile_path,$checksum,$key);
}


sub decrypt_snapshot_alpha{
	my $this = shift;
	
	my $full_path = shift;
	my $checksum = shift;
	my $key = shift;
	my $cipher = $this->get_symmetric_cipher($key);
	$cipher->start('decrypting');
	my $sha = Digest::SHA->new(256);
	my $buf;
	open(my $fh,'<',$full_path) || die "cannot open file";
	while(sysread($fh,$buf,8192)){
		$sha->add($buf);
		syswrite(STDOUT,$cipher->crypt($buf));
	}
	close($fh);
	syswrite(STDOUT,$cipher->finish());
		
}


=head1 AUTHOR

Joel De Jesus, C<< <dejesus.joel at e-flamingo.jp> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-backup-zfsonaws at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Backup-ZFSonAWS>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Backup::ZFSonAWS


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Backup-ZFSonAWS>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Backup-ZFSonAWS>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Backup-ZFSonAWS>

=item * Search CPAN

L<http://search.cpan.org/dist/Backup-ZFSonAWS/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

    ZFSonAWS is a program that automates backing up zfs snapshots onto AWS's S3.
    Copyright (C) 2015  Joel De Jesus

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


=cut

1; # End of Backup::ZFSonAWS
