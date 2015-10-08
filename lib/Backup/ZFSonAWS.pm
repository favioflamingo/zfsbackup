package Backup::ZFSonAWS;

use 5.006;
use strict;
use warnings FATAL => 'all';
use IO::Handle;
use Data::Dumper;
use Crypt::CBC;
use Digest::SHA qw(sha256_hex);
use JSON::XS;

=head1 NAME

Backup::ZFSonAWS - The great new Backup::ZFSonAWS!

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


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
	'recepient' => 'favio@example.com'
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
	
	if(defined $options->{'recepient'} && $options->{'recepient'} =~ m/^(.*)$/){
		$this->{'recepient'} = $1;
	}
	else{
		die "no gpg recepient provided";
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

sub recepient {
	return shift->{'recepient'};
}


sub add_pid {
	my $this = shift;
	my $pid = shift;
	if( defined $pid && $pid =~ m/^(\d+)$/){
		$pid = $1;
	}
	unless(defined $this->{'children'}){
		$this->{'children'} = {};
	}
	
	$this->{'children'}->{$pid} = 1;
	return scalar(keys %{$this->{'children'}});
}

sub remove_pid {
	my $this = shift;
	my $pid = shift;
	delete $this->{'children'}->{$pid};
}


=pod

---+ Main Subroutines


=cut

=pod

--++ wait_for_children()

When it is time to kill this object, we need to wait for all child processes to exit.

=cut

sub wait_for_children{
	my $this = shift;
	while(scalar(@{$this->{'children'}}) > 0){
		my $latestpid = shift(@{$this->{'children'}});
		warn "Waiting for $latestpid to exit";
		waitpid($latestpid,0);
	}
	warn "All children have exited";
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
			$data->{'incremental'}->{$1} = [] unless defined $data->{$1};
			#push(@{$data->{'incremental'}->{$1}},[$2,$3,$4,$5,$6,$7]);
			$data->{'incremental'}->{$1}->{$2.$3.$4}->{$5.$6.$7} = 1;
		}
		elsif($line =~ m/fullzfsbackup(.*)_(\d{4})(\d{2})(\d{2})/){
			$data->{'full'}->{$1} = [] unless defined $data->{$1};
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
	open(my $fh, "|-",'/usr/bin/gpg','--batch','--yes','-r',$this->recepient,'--armor','-o',$path,'-e','-') || die "cannot do gpg";
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
	
	my $pid = fork();
	if($pid > 0){
		print STDERR "Forking with pid=$pid to copy $s3path to aws";
		$this->add_pid($pid);
	}
	elsif($pid == 0){
		# child
		exec('/usr/local/bin/aws','s3','cp',$fpath,'s3://'.$this->bucket.'/'.$s3path) || die "failed to run";
		exit(0);
	}
	else{
		die "cannot fork to do aws cp";
	}
	
	my $oldpid = $pid;
	$pid = fork();
	if($pid > 0){
		# parent
		$this->add_pid($pid);
	}
	elsif($pid == 0){
		# this child's reason for existence is to delete the file being sent to aws without holding up the cpu intensive encryption process.
		waitpid($oldpid,0);
		unlink($fpath);
		exit(0);
	}
	else{
		die "cannot fork to do aws cp";
	}
}

=pod

---++ compress_zfs_send

Compress zfs with bzip2 -c

Return a file handle, on which a checksum and encryption operation is to take place

=cut

sub compress_zfs_send {
	my $this = shift;
	my $sendpath = shift;
	
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
		STDOUT->fdopen( $fhzfsout, 'w' ) or die $!;
		exec('/sbin/zfs','send',$sendpath);
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
		STDIN->fdopen( $fhbzipin,  'r' ) or die $!;
		STDOUT->fdopen( $fhbzipout, 'w' ) or die $!;
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
	
	my $zfspath = $fs;
	$zfspath =~ s/_/\//g;
	print STDERR "zfs backup($zfspath,$date)\n";
	# fullzfsbackup(.*)_(\d{4})(\d{2})(\d{2})
	print STDERR "...s3path=fullzfsbackup".$zfspath."_".$date."\n";
	#encrypt_txt('/tmp/test',generate_random_key(32));
	#open(my $fh, "-|",'/sbin/zfs','send',$zfspath.'@'.$date) || die "cannot do zfs backup";
	my $fh = $this->compress_zfs_send($zfspath.'@'.$date);
	
	open(my $fhout,'>',$this->tmppath.$fs.'_'.$date) || die "cannot write zfs to disk";
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
	cp_to_aws($this->tmppath.'/'.$fs.'_'.$date,$fs.'_'.$date);
	cp_to_aws($this->tmppath.'/'.$fs.'_'.$date.'.gpg',$fs.'_'.$date.'.gpg');

}

#incrementalzfsbackup(.*)_(\d{4})(\d{2})(\d{2})_(\d{4})(\d{2})(\d{2})

sub calculate_full {
	my $this = shift;
	my ($snaplocal,$snapaws) = (shift,shift);
	my $data = [];
	# find the first element of all zfs filesystem
	return undef unless defined $snaplocal && ref($snaplocal) eq 'HASH';
	# The format of $fs is tank_sub1_sub2 
	foreach my $fs (keys %{$snaplocal}){
		print STDERR "$fs\n";
		if(defined $snapaws->{'full'}->{$fs} && defined $snapaws->{'full'}->{$fs}->{$snaplocal->{$fs}->[0]}  ){
			print STDERR "...Full defined\n";
		}
		else{
			$this->backup_full($fs,join('',@{$snaplocal->{$fs}->[0]}));
		}
	}
	return $data;
}

sub run_backup {
	my $this = shift;
	
	# find out new full snapshots to take
	my $required_full = $this->calculate_full(
		$this->extract_zfs_snapshots(),
		$this->extract_aws_content()
	);


	# find out new incremental snaphosts


	# find out what snapshots to delete

	
}


=pod

Usage: ./recover.pl /tmp/checksumfile /tmp/snapshotfile 


=cut

sub get_options {
	my @args = @_;
	my $func = shift(@args);
	if($func eq 'recover'){
		return get_options_recover(@args);
	}
	elsif($func eq 'backup'){
		return get_options_backup(@args);
	}
	else{
		die "bad options";
	}
}

sub get_options_backup {
	my @args = @_;
	
	# read conf file
	my $path = '/etc/zfsbackup/backup.conf';
	die " no conf file exists" unless -f $path;
	open(my $fh, '<',$path) || die "cannot open file";
	my $x = '';
	while(<$fh>){ $x .= $_;}
	close($fh);
	
	return JSON::XS::decode_json($x);
}


sub get_options_recover {
	my @args = @_;
	my $data = {};
	die " no clear text key and checksum file" unless -f $args[0];
	if($args[0] =~ m/^(.*)$/){
		$data->{'checksumfile'} = $args[0];
	}
	die " no cipher text zfs snapshot" unless defined $args[1];
	if($args[1] =~ m/^(.*)$/){
		$data->{'snapshotfile'} = $args[1];
	}
	
	return $data;
}


sub extract_key_checksum {
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

sub get_symmetric_cipher{
	my $key = shift;
	return Crypt::CBC->new(-key => $key, -cipher => 'Blowfish');
}

# 
sub decrypt_full_backup{
	my $full_path = shift;
	my $checksum = shift;
	my $key = shift;
	my $cipher = get_symmetric_cipher($key);
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


#my ($checksum,$key) = extract_key_checksum('/tmp/unretard.txt');

#print STDERR "[".length($checksum).",".length($key)."]"



my $options = get_options(@ARGV);

#my $xo = Data::Dumper::Dumper($options);
#print STDERR $xo;

 ($options->{'checksum'},$options->{'key'}) = extract_key_checksum($options->{'checksumfile'});
my $xo = Data::Dumper::Dumper($options);
print STDERR $xo;

print STDERR "Now decrypting the full backup\n";
decrypt_full_backup($options->{'snapshotfile'},$options->{'checksum'},$options->{'key'});





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
