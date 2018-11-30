# mftdump2bodyfile
Convert mftdump file to Bodyfile TSK 3.x


First step :
Grab mftdump.exe from #http://malware-hunters.net/all-downloads/ Tested with version 2012-09-13 MFTDump V.1.3.0

Second step:
- Create an mftdump file from your freshly extracted NTFS $MFT :
--- Syntax : mftdump.exe /d /l /m <string : hostname or case identifier> /o <mftdump_file.txt> /v <$MFT>
--- Sample : mftdump.exe /d /l /m <vegeta2206host> /o <mftdump_vegeta2206.txt> /v <$MFT>

Third step : 
- Create your bodyfile TSK from mftdump file :
--- Syntax : ./parse_mftdump.pl <mftdump_vegeta2206.txt> >> <mftdump_vegeta2206.bodyfile>

Check out this blog post on MFT parser testing here: http://az4n6.blogspot.com/2015/09/whos-your-master-mft-parsers-reviewed.html
