package Backup::ZFSonAWS;

use 5.006;
use strict;
use warnings FATAL => 'all';

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

=cut



my $bucket = $ARGV[0];
my $recepient = $ARGV[1];
die "no proper args" unless defined $bucket && $recepient;
my $tmp_path = '/var/backup';
my $varbackup = 'storage-space/tmpbackup';
# aws s3 ls s3://putS3BucketHeres
my @awspids;


=pod

---++ extract_zfs_snapshots

Run zfs list -t snapshot and get a list of all the snapshots.

=cut

sub extract_zfs_snapshots {
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
	my $pid = open(my $fh,"-|",'/usr/local/bin/aws','s3','ls','s3://'.$bucket) || die "cannot extract aws stuff";
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
	my $path = shift;
	my $txt = shift;
	# /usr/bin/gpg -r dejesus.joel@e-flamingo.jp --armor -o - -e -
	open(my $fh, "|-",'/usr/bin/gpg','--batch','--yes','-r',$recepient,'--armor','-o',$path,'-e','-') || die "cannot do gpg";
	syswrite($fh,$txt);
	close($fh);
}

sub generate_random_key {
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
	if($num =~ m/^(.*)$/){
		$num = $1;
	}
	return $num;
}

sub get_symmetric_cipher{
	my $key = shift;
	return Crypt::CBC->new(-key => $key, -cipher => 'Crypt::OpenSSL::AES');
}

sub cp_to_aws{
	my ($fpath,$s3path) = (shift,shift);
	
	my $pid = fork();
	if($pid > 0){
		print STDERR "Forking with pid=$pid to copy $s3path to aws";
	}
	elsif($pid == 0){
		# child
		system('/usr/local/bin/aws','s3','cp',$fpath,'s3://'.$bucket.'/'.$s3path) || die "failed to run";
		unlink($fpath);
		exit(0);
	}
	else{
		die "cannot fork to do aws cp";
	}
}


sub backup_full {
	my ($fs,$date) = (shift,shift);
	my $zfspath = $fs;
	$zfspath =~ s/_/\//g;
	print STDERR "zfs backup($zfspath,$date)\n";
	# fullzfsbackup(.*)_(\d{4})(\d{2})(\d{2})
	print STDERR "...s3path=fullzfsbackup".$zfspath."_".$date."\n";
	#encrypt_txt('/tmp/test',generate_random_key(32));
	open(my $fh, "-|",'/sbin/zfs','send',$zfspath.'@'.$date) || die "cannot do zfs backup";
	open(my $fhout,'>','/var/backup/'.$fs.'_'.$date) || die "cannot write zfs to disk";
	my $i = 0;
	my $buf;
	my $sha = Digest::SHA->new(256);
	my $key = generate_random_key(32);
	my $cipher = get_symmetric_cipher($key);
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
	encrypt_txt('/var/backup/'.$fs.'_'.$date.'.gpg',pack('L',length($checksum )).$checksum.pack('L',length($key )).$key  );
	cp_to_aws('/var/backup/'.$fs.'_'.$date,$fs.'_'.$date);
	cp_to_aws('/var/backup/'.$fs.'_'.$date.'.gpg',$fs.'_'.$date.'.gpg');

	# /sbin/zfs send $fs@$date | tee /var/backup/$fs_$date | sha256sum - > /var/backup/$
#	system("/sbin/zfs send $zfspath\@$date | tee /var/backup/$fs_$date | sha256sum - > /var/backup/$fs_$date.checksum ") 		|| die "failed to run zfs send";

	#system('/usr/local/bin/aws','s3','') || die "failed to run backup";	
}

#incrementalzfsbackup(.*)_(\d{4})(\d{2})(\d{2})_(\d{4})(\d{2})(\d{2})

sub calculate_full {
	my ($snaplocal,$snapaws) = (shift,shift);
	my $data = [];
	# find the first element of all zfs filesystem
	return undef unless defined $snaplocal && ref($snaplocal) eq 'HASH';
	foreach my $fs (keys %{$snaplocal}){
		print STDERR "$fs\n";
		if(defined $snapaws->{'full'}->{$fs} && defined $snapaws->{'full'}->{$fs}->{$snaplocal->{$fs}->[0]}  ){
			print STDERR "...Full defined\n";
		}
		else{
			backup_full($fs,join('',@{$snaplocal->{$fs}->[0]}));
		}
	}
	return $data;
}

sub run_backup {
	my $snapshots_local = extract_zfs_snapshots();

	my $snapshots_aws = extract_aws_content();

	# find out new full snapshots to take
	my $required_full = calculate_full($snapshots_local,$snapshots_aws);


	# find out new incremental snaphosts


	# find out what snapshots to delete

	
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

Copyright 2015 Joel De Jesus.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=cut

1; # End of Backup::ZFSonAWS
