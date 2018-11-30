#!/usr/bin/perl

#parse_mftdump.pl v.1.0
#Daolam Trinh Huu Phap
#
#
#Parses the output of mftdump.exe from the Standard Format to bodyfile format
#Grab mftdump.exe from #http://malware-hunters.net/all-downloads/
#Tested with version 2012-09-13 MFTDump V.1.3.0
#
#First, create and mftdump output file with mftdump.exe downloaded from malware-hunters using the syntax:
#	mftdump.exe /d /l /m <hostname> /o <output filename> /v <Extracted $MFT>
#
#Then run this tool over the mft_output.txt to create a bodyfile
#       parse_mftdump.pl C:/path/to/mft_output.txt >> C:/path/to/bodyfile.txt
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You can view the GNU General Public License at <http://www.gnu.org/licenses/>
#


use Time::Local;
use POSIX 'strftime';
use Time::Piece;


sub getUnixTime() {
        my ($date)=@_;
#	print "getUnixTime($date)=";
	chomp($date);
	my $tp = Time::Piece->strptime("$date","%Y-%m-%d %H:%M:%S");
	my $time=$tp->epoch;
#	print "$time\n";
        return $time;
}

open(MFTDUMPFILE, "<$ARGV[0]") or die "Unable to read MFTDump file ! \n";

=begin comment
=end comment
=cut

$cnt=0;
while($line=<MFTDUMPFILE>) {
	chomp($line);
#	print "===LINE:$line===\n";

	if ($cnt==0) {

		if ($line =~/^RecNo.*Hostname$/gi) {
			@cols=split('\t',$line);
			for ($i=0;$i<scalar(@cols);$i++) {
				$cols[$i] =~s/\ \(UTC\)/UTC/g;
				print $cols[$i].'=$'.$cols[$i]."|";
			}
			####################
			# Good input file
			####################
			print "##################################################################\n\n";
			print "Your mftdump file looks GOOD :-)\n\n";
			print "##################################################################\n\n";
			print "TSK 3.x format\n";
			print "\t#bodyfile format; http://wiki.sleuthkit.org/index.php?title=Body_file\n";
			print "\t#MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime\n\n";

		} else {
                	####################
                	# Bad input file
                	####################		
			print "##################################################################\n\n";
			print "\tYour MFTdump file looks BAD !\n\a\n";
			print "\tExiting !\n\n";
			print "##################################################################\n\n";
			exit(1);
		}

	} else {

		@data=split('\t', $line);
		for ($o=0;$o<scalar(@data);$o++) {
			#print "$cols[$o] => $data[$o]\n";
		}

		$RecNo=$data[0];
		$Deleted=$data[1];
		$Directory=$data[2];
		$ADS=$data[3];
		$Filename=$data[4];
		$DOSFilename=$data[5];
		$siCreateTimeUTC=&getUnixTime($data[6]);
		$siAccessTimeUTC=&getUnixTime($data[7]);
		$siModTimeUTC=&getUnixTime($data[8]);
		$siMFTModTimeUTC=&getUnixTime($data[9]);
		$ActualSize=$data[10];
		$AllocSize=$data[11];
		$Ext=$data[12];
		$FullPath=$data[13];
		$fnCreateTimeUTC=&getUnixTime($data[14]);
		$fnAccessTimeUTC=&getUnixTime($data[15]);
		$fnModTimeUTC=&getUnixTime($data[16]);
		$fnMFTModTimeUTC=&getUnixTime($data[17]);
		$ReadOnly=$data[18];
		$Hidden=$data[19];
		$System=$data[20];
		$Resident=$data[21];
		$Archive=$data[22];
		$Compressed=$data[23];
		$Device=$data[24];
		$Encrypted=$data[25];
		$Indexed=$data[26];
		$Normal=$data[27];
		$Offline=$data[28];
		$ReparsePoint=$data[29];
		$SparseFile=$data[30];
		$Temporary=$data[31];
		$Hostname=$data[32];
		#print "\nRecNo=$RecNo|Deleted=$Deleted|Directory=$Directory|ADS=$ADS|Filename=$Filename|DOSFilename=$DOSFilename|siCreateTimeUTC=$siCreateTimeUTC|siAccessTimeUTC=$siAccessTimeUTC|siModTimeUTC=$siModTimeUTC|siMFTModTimeUTC=$siMFTModTimeUTC|ActualSize=$ActualSize|AllocSize=$AllocSize|Ext=$Ext|FullPath=$FullPath|fnCreateTimeUTC=$fnCreateTimeUTC|fnAccessTimeUTC=$fnAccessTimeUTC|fnModTimeUTC=$fnModTimeUTC|fnMFTModTimeUTC=$fnMFTModTimeUTC|ReadOnly=$ReadOnly|Hidden=$Hidden|System=$System|Resident=$Resident|Archive=$Archive|Compressed=$Compressed|Device=$Device|Encrypted=$Encrypted|Indexed=$Indexed|Normal=$Normal|Offline=$Offline|ReparsePoint=$ReparsePoint|SparseFile=$SparseFile|Temporary=$Temporary|Hostname=$Hostname\n";

		$FullPath=$FullPath." (DELETED)" if ($Deleted==1);
		$ActualSize=0 if (length($ActualSize)==0);

		# Standard Infos
		#print "0|$FullPath|0|0|0|0|0|$ActualSize|$siAccessTimeUTC|$siModTimeUTC|$siMFTModTimeUTC|$siCreateTimeUTC\n";

		# FN Infos
		print "0|$FullPath|0|0|0|0|$ActualSize|$fnAccessTimeUTC|$fnModTimeUTC|$fnMFTModTimeUTC|$fnCreateTimeUTC\n";

	}

	$cnt++; #next line number

} #end while
close(MFTDUMPFILE);


