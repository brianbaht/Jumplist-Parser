import struct
from datetime import datetime, timezone
import sys, getopt
stop_int = -2
free_space_int = -1
ole_header = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
big_endian = b'\xff\xfe'
little_endian = b'\xfe\xff'
msat_max_sectors = 109
header_size = 512
endian = ""
sat_magic = -3
sid_size = 4
jle_file = None
jle_file_name = None
jle_type = None
dir_entry_size = 128
root_type = 5
empty_type = 0
storage_type = 1
stream_type = 2
lock_type = 3
property_type = 4
root_entry_str = "Root Entry"
dir_dest_list_str = "DestList"
version_size = 4
dest_list_header_size = 32
dest_list_entry_id_offset = 88
version_one = 1
version_three = 3
version_one_entry_id_size = 8
version_three_entry_id_size = 4
dest_list_path_size = 2
version_one_path_size_offset = 112
version_three_path_size_offset = 128
version_one_entry_path_offset = 114
version_three_entry_path_offset = 130
lnk_header_size = 8
lnk_magic = 584944480944204
lnk_filetime_size = 8
lnk_creation_start = 28
lnk_lastaccess_start = 36
lnk_lastmodify_start = 44

#Used to get number out of tuple
def unpack_bytes(format, buf):
	return struct.unpack(endian + format, buf)[0]

def get_bytes(start_sid, sector_size, whole_file, root = b''):
	if(len(root) == 0):
		return whole_file[header_size + (sector_size * start_sid):sector_size + header_size + (sector_size * start_sid)]
	else:
		return root[sector_size * start_sid:sector_size + (sector_size * start_sid)]

def check_size(min_sector_size, size):
	return size >= min_sector_size

def get_data_run(start_sid, allocation_arr, sector_size, whole_file, root=b''):
	sid_loc = start_sid
	data_bytes = b''
	while(sid_loc != stop_int):
		if(len(root) == 0):
			data_bytes += get_bytes(sid_loc, sector_size, whole_file)
		else:
			data_bytes += get_bytes(sid_loc, sector_size, whole_file, root)
		sid_loc = allocation_arr[sid_loc]
	return data_bytes

#parse LNK file header
def parse_lnk(lnk_bytes):
	header = int(unpack_bytes("q", lnk_bytes[:lnk_header_size]))
	lnk_dict = {}
	if(header == lnk_magic):
		lnk_dict["creation"] = unpack_bytes("q", lnk_bytes[lnk_creation_start:lnk_filetime_size + lnk_creation_start])
		lnk_dict["last_access"] = unpack_bytes("q", lnk_bytes[lnk_lastaccess_start:lnk_filetime_size + lnk_lastaccess_start])
		lnk_dict["last_modify"] = unpack_bytes("q", lnk_bytes[lnk_lastmodify_start:lnk_filetime_size + lnk_lastmodify_start])
		return lnk_dict
	else:
		return lnk_dict

def convert_timestamp(timestamp):
	unix_epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
	windows_epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
	epoch_delta = unix_epoch - windows_epoch
	windows_timestamp_in_seconds = timestamp / 10_000_000
	unix_timestamp = windows_timestamp_in_seconds - epoch_delta.total_seconds()
	return datetime.utcfromtimestamp(unix_timestamp)

#Get MSAT array
def extract_og_msat(msat_bytes):
	counter = 0
	sid = unpack_bytes("i", msat_bytes[counter*sid_size:(counter*sid_size) + sid_size])
	msat_arr = []
	while(sid != free_space_int):
		msat_arr.append(sid)
		counter += 1
		if(counter == msat_max_sectors):
			break
		sid = msat_bytes[counter*sid_size:(counter*sid_size) + sid_size]
		sid = unpack_bytes("i", sid)
	return msat_arr

#Extract SAT bytes
def get_sat(msat_arr, sect_size, rest_of_file):
	sat = b''
	for sid in msat_arr:
		offset = (sid * sect_size)
		sat += rest_of_file[offset:offset + sect_size]
	return sat

#Extract SAT array from bytes
def extract_sat_arr(sat_byte_arr):
	counter = 0
	sat_arr = []
	num_sat_sids = int(len(sat_byte_arr)/sid_size)
	sid = unpack_bytes("i", sat_byte_arr[counter*sid_size:(counter*sid_size) + sid_size])
	if(sid != sat_magic):
		print("Error in extracting SAT table")
		exit()
	for i in range(0,num_sat_sids):
		sid = unpack_bytes("i", sat_byte_arr[i * sid_size:(sid_size*i) + sid_size])
		sat_arr.append(sid)
	return sat_arr

def get_ssat(ssat_start, sector_size, ssat_length, rest_of_file):
	offset_start = ssat_start * sector_size
	ssat_arr = []
	num_sids = int((ssat_length * sector_size)/sid_size)
	for i in range(0,num_sids):
		ssat_arr.append(unpack_bytes("i", rest_of_file[offset_start + (sid_size * i):offset_start + sid_size + (sid_size * i)]))
	return ssat_arr

#Extract directory bytes using SAT
def get_directory_bytes(directory_start, sat_arr, sector_size, whole_file):
	sat_location = directory_start
	dir_bytes = b''
	offset = (sat_location * sector_size) + header_size
	while(sat_location != stop_int):
		dir_bytes += whole_file[offset:offset + sector_size]
		sat_location = sat_arr[sat_location]
		offset = (sat_location * sector_size) + header_size
	return dir_bytes

def parse_directory(dir_bytes):
	num_dirs = int(len(dir_bytes)/dir_entry_size)
	dir_dict = {}
	for i in range(0, num_dirs):
		dir_entry = dir_bytes[dir_entry_size * i:(dir_entry_size * i) + dir_entry_size]
		dir_name_bytes = dir_entry[0:64]
		dir_name = dir_name_bytes.decode("utf-16").rstrip("\x00")
		dir_dict[dir_name] = dir_entry
	return dir_dict

def extract_dir_entry(dir_entry_bytes):
	dir_entry_dict = {}
	dir_entry_dict["created"] = unpack_bytes("q", dir_entry_bytes[100:108])
	dir_entry_dict["modified"] = unpack_bytes("q", dir_entry_bytes[108:116])
	dir_entry_dict["sid"] = unpack_bytes("i", dir_entry_bytes[116:120])
	dir_entry_dict["size"] = unpack_bytes("i", dir_entry_bytes[120:124])
	return dir_entry_dict

def extract_destlist_entry(destlist_bytes, version, start_byte):
	destlist_entry_dict = {}
	if(version == version_one):
		#print(start_byte)
		destlist_entry_dict["entry_id"] = unpack_bytes("q", destlist_bytes[start_byte + dest_list_entry_id_offset:start_byte + dest_list_entry_id_offset + version_one_entry_id_size])
		destlist_entry_dict["path_length"] = (unpack_bytes("h", destlist_bytes[start_byte + version_one_path_size_offset:start_byte + version_one_path_size_offset + dest_list_path_size]) * 2)
		destlist_entry_dict["path"] = destlist_bytes[start_byte + version_one_entry_path_offset:start_byte + version_one_entry_path_offset + destlist_entry_dict["path_length"]].decode("utf-16")
		#print(destlist_entry_dict["path"])
		return destlist_entry_dict
	elif(version == version_three):
		destlist_entry_dict["entry_id"] = unpack_bytes("i", destlist_bytes[start_byte + dest_list_entry_id_offset:start_byte + dest_list_entry_id_offset + version_three_entry_id_size])
		destlist_entry_dict["path_length"] = unpack_bytes("h", destlist_bytes[start_byte + version_three_path_size_offset:start_byte + version_three_path_size_offset + dest_list_path_size])
		destlist_entry_dict["path"] = destlist_bytes[start_byte + version_three_entry_path_offset:start_byte + version_three_entry_path_offset + destlist_entry_dict["path_length"]].decode("utf-16")
		return destlist_entry_dict
	else:
		return destlist_entry_dict

def main(argv):
	inputfile = ''
	try:
		opts, args = getopt.getopt(argv,"ht:i:",["type=", "ifile="])
	except getopt.GetoptError:
		print('jleparse.py -t <jumplist type (c = custom, a = automatic)> -i <inputfile>')
		sys.exit(2)
	if(len(argv) < 3):
		print('jleparse.py -t <jumplist type (c = custom, a = automatic)> -i <inputfile>')
		sys.exit(2)
	for opt, arg in opts:
		if(opt == "-h"):
			print('jleparse.py -t <jumplist type (c = custom, a = automatic)> -i <inputfile>')
			sys.exit()
		elif(opt in ("-t", "--type")):
			jle_type = arg
		elif(opt in ("-i", "--ifile")):
			jle_file_name = arg
	jle_file = open(jle_file_name, "rb")
	header = jle_file.read(header_size)
	jle_file.seek(header_size)
	rest_of_file = jle_file.read()
	jle_file.seek(0)
	whole_file = jle_file.read()
	file_sig = header[0:8]
	#Verify file is OLE file type
	if(file_sig != ole_header):
		print("The specified file is not of type OLE")
		exit()

	#Get little endian or big endian
	endian_header = header[28:30]

	if(endian_header == big_endian):
		endian = ">"

	elif(endian_header == little_endian):
		endian = "<"

	#Get sector size
	sector_size_header = header[30:32]
	short_sector_size_header = header[32:34]
	#get sector allocation table size
	sat_size_header = header[44:48]
	#get directory first sector SID
	directory_first_sector_sid_header = header[48:52]
	#get min size of standard stream
	min_stream_size_header = header[56:60]
	#get Sector identifier (SID) of first sector of the short-sector allocation table (SSAT).
	short_first_sector_sid_header = header[60:64]
	#Get Total number of sectors used for the short-sector allocation table (SSAT).
	total_sectors_ssat_header = header[64:68]
	#Get Sector identifier (SID) of first sector of the extra master sector allocation table (MSAT)
	extra_msat_first_sid_header = header[68:72]
	#Get Total number of sectors used for the master sector allocation table (MSAT).
	total_sectors_msat_header = header[72:76]
	#Get First part of the master sector allocation table (MSAT) containing 109 sector identifiers (SIDs).
	og_msat = header[76:512]


	sector_size = 2**unpack_bytes("h", sector_size_header)
	short_sector_size = 2**unpack_bytes("h", short_sector_size_header)

	#Extract msat
	msat_arr = extract_og_msat(og_msat)

	#Get SAT
	sat_byte_arr = get_sat(msat_arr, sector_size, rest_of_file)

	#Convert SAT byte arr to decimal
	sat_arr = extract_sat_arr(sat_byte_arr)
	#Convert ssat size byte arr to decimal
	total_sectors_ssat = unpack_bytes("i", total_sectors_ssat_header)

	#Get decimal of first SSAT value
	short_first_sector_sid = unpack_bytes("i", short_first_sector_sid_header)

	#Get SSAT 
	if(short_first_sector_sid > 0):
		ssat_arr = get_ssat(short_first_sector_sid, sector_size, total_sectors_ssat, rest_of_file)

	#Convert directory start sid to decimal
	directory_first_sector_sid = unpack_bytes("i", directory_first_sector_sid_header)

	#Get Directory bytes
	directory_bytes = get_directory_bytes(directory_first_sector_sid, sat_arr, sector_size, whole_file)

	#Parse directory
	dir_dict = parse_directory(directory_bytes)

	#Extract root dir
	root_entry_bytes = dir_dict[root_entry_str]

	#Extract dest list entry
	dest_list_entry_bytes = dir_dict[dir_dest_list_str]

	#Convert min stream size bytes
	min_stream_size = unpack_bytes("i", min_stream_size_header)

	#Extract dest list from bytes
	dest_list_entry_dict = extract_dir_entry(dest_list_entry_bytes)

	#Extract root from bytes
	root_entry_dict = extract_dir_entry(root_entry_bytes)

	#Get Root data
	root_data = b''
	if(check_size(min_stream_size, root_entry_dict["size"])):
		root_data = get_data_run(root_entry_dict["sid"], sat_arr, sector_size, whole_file)
	else:
		root_data = get_data_run(root_entry_dict["sid"], ssat_arr, sector_size, whole_file)
	#Get Dirlist data
	dir_list_full_data = b''
	if(check_size(min_stream_size, dest_list_entry_dict["size"])):
		dest_list_full_data = get_data_run(dest_list_entry_dict["sid"], sat_arr, sector_size, whole_file)
	else:
		dest_list_full_data = get_data_run(dest_list_entry_dict["sid"], ssat_arr, short_sector_size, whole_file, root_data)

	#Parse Dirlist data
	entry_remain = True
	start_point = 0
	version = unpack_bytes("i", dest_list_full_data[0:4])
	dest_list_data = dest_list_full_data[dest_list_header_size:]
	dest_list_entries = []
	while(entry_remain):
		entry_remain = False
		new_dest_list_entry = extract_destlist_entry(dest_list_data, version, start_point)
		dest_list_entries.append(new_dest_list_entry)
		if(version == version_one):
			start_point += version_one_entry_path_offset + new_dest_list_entry["path_length"]
			length_rest = len(dest_list_data[start_point:])
			if(length_rest > version_one_entry_path_offset):
				entry_remain = True
		elif(version == version_three):
			start_point += version_three_entry_path_offset + new_dest_list_entry["path_length"]
			length_rest = len(dest_list_data[start_point:])
			if(length_rest > version_three_entry_path_offset):
				entry_remain = True
	#Loop through destlist entries
	for destlist_entry in dest_list_entries:
		if(destlist_entry["entry_id"] != 0):
			entry = extract_dir_entry(dir_dict[str(destlist_entry["entry_id"])])
			if(check_size(min_stream_size, entry["size"])):
				entry_data = get_data_run(entry["sid"], sat_arr, sector_size, whole_file)
			else:
				entry_data = get_data_run(entry["sid"], ssat_arr, short_sector_size, whole_file, root_data)
			lnk_dict = parse_lnk(entry_data)
			lnk_dict["creation"] = convert_timestamp(lnk_dict["creation"]).strftime("%m/%d/%Y %H:%M:%S")
			lnk_dict["last_access"] = convert_timestamp(lnk_dict["last_access"]).strftime("%m/%d/%Y %H:%M:%S")
			lnk_dict["last_modify"] = convert_timestamp(lnk_dict["last_modify"]).strftime("%m/%d/%Y %H:%M:%S")
			print("Path: " + destlist_entry["path"])
			print("Lnk Creation: " + lnk_dict["creation"])
			print("Lnk Last Access: " + lnk_dict["last_access"])
			print("Lnk Last Modify: " + lnk_dict["last_modify"])
			print()

if __name__ == "__main__":
	main(sys.argv[1:])
