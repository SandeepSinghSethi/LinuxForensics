#!/usr/bin/env python3

import binascii
import json
import struct
import time
import os.path
import sys
import argparse
from math import log

class MBR():
    def __init__(self,sector,partno,isext,extpart):
        self.partno = partno
        if(isext == 1):
            self.partno = extpart
        offset = 446 + partno*16
        self.active = False
        if(sector[offset] == 0x80):
            self.active = True
        self.type = sector[offset+4]
        self.empty = 0
        if(self.type == 0x00):
            self.empty = 1
        self.start = sector[offset+8] + sector[offset+9] * 256 + sector[offset+10] *256*256 + sector[offset+11] *256*256*256
        self.sector = (sector[offset+12]) + (sector[offset+13]) * 256 + (sector[offset+14]) *256*256 + (sector[offset+15]) *256*256*256

extguid = '0FC63DAF-8483-4772-8E79-3D69D8477DE4'
def printGuid(packedString):
   if len(packedString) == 16:
      outstr = format(struct.unpack('<L', packedString[0:4])[0], 'X').zfill(8) + "-" + \
         format(struct.unpack('<H', packedString[4:6])[0], 'X').zfill(4) + "-" + \
         format(struct.unpack('<H', packedString[6:8])[0], 'X').zfill(4) + "-" + \
         format(struct.unpack('>H', packedString[8:10])[0], 'X').zfill(4) + "-" + \
         format(struct.unpack('>Q', b"\x00\x00" + packedString[10:16])[0], 'X').zfill(12)
   else:
       outstr = "<invalid>" 
   return outstr

class GptRecord():
   def __init__(self, recs, partno):
      self.partno = partno
      offset = partno * 128
      self.empty = False
      # build partition type GUID string
      self.partType = printGuid(recs[offset:offset+16])
      if self.partType == "00000000-0000-0000-0000-000000000000":
         self.empty = True
      self.partGUID = printGuid(recs[offset+16:offset+32]) 
      self.firstLBA = struct.unpack('<Q', recs[offset+32:offset+40])[0]
      self.lastLBA = struct.unpack('<Q', recs[offset+40:offset+48])[0]
      self.attr = struct.unpack('<Q', recs[offset+48:offset+56])[0]
      nameIndex = recs[offset+56:offset+128].find(b'\x00\x00')
      if nameIndex != -1:
         self.partName = recs[offset+56:offset+56+nameIndex].replace(b'\x00',b'')
      else:
         self.partName = recs[offset+56:offset+128].replace(b'\x00',b'')

   def printPart(self):
       if not self.empty:
           outstr = str(self.partno) + ":" + str(self.partType) + ":" + str(self.partGUID) + \
            ":" + str(self.firstLBA) + ":" + str(self.lastLBA) + ":" + \
            str(self.attr) + ":" + str(self.partName)
           print(outstr)

def printpart(mbrlist):
    lst = mbrlist
    for i in lst:
        if i.empty == True:
            print(f"Partition {i.partno} is <empty>")
        else:
            print(f"Partition {i.partno} info : ")
            print(f"\tIsActive = {i.active}")
            print(f"\tPartition Type = {hex(i.type)}")
            print(f"\tStart Offset = {i.start}")
            print(f"\tTotal Sector = {i.sector}")


def printUuid(data):
    retStr = format(struct.unpack('<Q', data[8:16])[0], 'X').zfill(16) + format(struct.unpack('<Q', data[0:8])[0], 'X').zfill(16)
    return retStr


def getU32(data,offset=0):
    return struct.unpack('<L',data[offset:offset+4])[0]


def getU16(data,offset=0):
    return struct.unpack('<H',data[offset:offset+2])[0]

def getU8(data,offset=0):
    return struct.unpack('B',data[offset:offset+1])[0]


def getU64(data,offset=0):
    return struct.unpack('<Q',data[offset:offset+8])[0]

def getU128(data,offset=0):
    return data[offset:offset+16]


# getting compatibility , incompatibility and read only compatibility features from the attributes of sb

def compatibilityFeatures(f):
    lst = []
    # f is a bitset , the number f in binary display its features , see ext4.kernel.org
    if f & 0x1:
        lst.append("Directory Preallocation")
    if f & 0x2:
        lst.append("Imagic Inodes")
    if f & 0x4:
        lst.append("Journal")
    if f & 0x8:
        lst.append("Extended Attributes")
    if f & 0x10:
        lst.append("Resize Inode")
    if f & 0x20:
        lst.append("Directory Indices")
    if f & 0x40:
        lst.append("Lazy Block Groups")
    if f & 0x80:
        lst.append("Exclude Inodes")
    if f & 0x100:
        lst.append("Exclude Bitmap")
    if f & 0x200:
        lst.append("Sparse Super 2")

    return lst

def incompatibilityFeatures(f):
    lst = []
    if f & 0x1:
        lst.append("Compression")
    if f & 0x2:
        lst.append("Incompat Filetype")
    if f & 0x4:
        lst.append("Recover")
    if f & 0x8:
        lst.append("Seperate Journal/Journal Device")
    if f & 0x10:
        lst.append("Meta Block Groups")
    if f & 0x40:
        lst.append("Extents")
    if f & 0x80:
        lst.append("64bit")
    if f & 0x100:
        lst.append("Mulitple mount protection")
    if f & 0x200:
        lst.append("Flexible Block Groups")
    if f & 0x400:
        lst.append("Extended Attributes in Inodes")
    if f & 0x1000:
        lst.append("Directory Data")
    if f & 0x2000:
        lst.append("Block Group MetaData Csum")
    if f & 0x4000:
        lst.append("Large Directory")
    if f & 0x8000:
        lst.append("Meta Block Groups")
    if f & 0x10000:
        lst.append("Encrypted Inodes")

    return lst

def readOnlyCompatibilityFeatures(f):
    lst = []
    if f & 0x1:
        lst.append("Sparse Superblock")
    if f & 0x2:
        lst.append("Large File")
    if f & 0x4:
        lst.append("Btree Directory")
    if f & 0x8:
        lst.append("Huge File")
    if f & 0x10:
        lst.append("Group Descriptor Table Csum")
    if f & 0x20:
        lst.append("Directory Nlink")
    if f & 0x40:
        lst.append("Extra Size/Large Inodes")
    if f & 0x80:
        lst.append("Snapshot")
    if f & 0x100:
        lst.append("Quota")
    if f & 0x200:
        lst.append("Big Alloc")
    if f & 0x400:
        lst.append("Metadata Csum")
    if f & 0x800:
        lst.append("Replicas")
    if f & 0x1000:
        lst.append("Read Only Disk")
    if f & 0x2000:
        lst.append("Project Quota")
    if f & 0x8000:
        lst.append("Verity Inodes")

    return lst

# see ext4.wiki.kernel.org for this structure dissection
class SuperBlock():
    def __init__(self,data):
        self.totalInode = getU32(data)   # 4bytes
        self.totalBlocks = getU32(data,0x4) # 4 byte starts at 4th offset
        self.restrictedBlocks = getU32(data,0x8) # 4bytes
        self.freeBlock = getU32(data,0xc)
        self.freeInode = getU32(data,0x10)
        self.firstDataBlock = getU32(data,0x14) # normally 0 if <4096
        self.blockSize =  pow(2 ,(10 + getU32(data,0x18)))
        self.clusterSize = pow(2,(10 + getU32(data,0x1C))) # if bigalloc feature is enabled otherwise is equal to blockSize
        self.blocksPerGroup = getU32(data,0x20)
        self.clustersPerGroup = getU32(data,0x24) # if bigalloc feature is enabled otherwise is equal to blocksPerGroup
        self.inodesPerGroup = getU32(data,0x28)
        self.mountTime = time.gmtime(getU32(data,0x2c)) # it was in second since epoch
        self.writeTime = time.gmtime(getU32(data,0x30))
        self.mountCount = getU16(data,0x34) # 2bytes
        self.maxMountCount = getU16(data,0x36) # max mount count until a fsck is needed , for regular checkup purposes
        self.magicSig = getU16(data,0x38) # should be 0xef53 
        self.state = getU16(data,0x3a) # 1,2,4 = cleanly unmounted , errors , orphans being recovred
        self.errors = getU16(data,0x3c) # behaviour when detecting errors 1/2/3 = continue,remount read-only,panic
        self.minorRevision = getU16(data,0x3e)
        self.lastcheck = time.gmtime(getU32(data,0x40))
        self.checkInterval = (getU32(data,0x44))
        self.creatorOS = getU32(data,0x48) # 0/1/2/3/4 = Linux/Hurd/Masix/FreeBSD/Lites
        self.revisionLevel = getU32(data,0x4c)
        self.defaultResUID = getU16(data,0x50) # uid for reserved blocks
        self.defaultResGID = getU16(data,0x52) # gid for reserved blocks
        self.firstNonReserveInode = getU32(data,0x54) # first  inode
        self.inodeSize = getU16(data,0x58) # inode size in bytes
        self.blockGroupNumber = getU16(data,0x5a) # block group this superblock is in
        self.compatibleFeatures = getU32(data,0x5c)
        self.compatibleFeaturesList = compatibilityFeatures(self.compatibleFeatures)
        self.incompatibleFeatures = getU32(data,0x60)
        self.incompatibleFeaturesList = incompatibilityFeatures(self.incompatibleFeatures)
        self.readOnlyCompatibleFeatures = getU32(data,0x64)
        self.readOnlyCompatibleFeaturesList = readOnlyCompatibilityFeatures(self.readOnlyCompatibleFeatures)
        self.volumeUUID = getU128(data,0x68)
        self.volumeName = data[0x78:0x88].split(b'\x00')[0]
        self.lastmountDirName = data[0x88:0xC8].split(b'\x00')[0]
        self.algorithmUsageBitmap = getU32(data,0xc8) # used with compression
        self.preallocBlocks = getU8(data,0xcc) #not in ext4 , used to preallocate blocks for files
        self.preallocDirBlocks = getU8(data,0xcd) # used to prealloc blocks for directories , only used with dir_prealloc feature
        self.reservedGDTBlocks = getU16(data,0xce)# blocks reserved for future expansion
        self.journalUUID = getU128(data,0xd0)
        self.journalInodeNum = getU32(data,0xe0) # inum of journal file
        self.journalDeviceNum = getU32(data,0xe4) # device number of journal if external journal is used
        self.lastOrphan = getU32(data,0xe8) # startlist of orphan inodes to delete
        self.hashseed = [getU32(data,0xec),getU32(data,0xf0),getU32(data,0xf4),getU32(data,0xf8)] # htree hash seed
        self.hashVersion = getU8(data,0xfc) # 0/1/2/3/4/5 legacy/half md4/tea/legacy unsigned/half md4,unsigned / tea unsigned
        self.journalBackupType = getU8(data,0xfd) # 0/1 to state whether it is used to store inode table as backup
        self.groupDescriptorSz = getU16(data,0xfe)
        self.defaultMountOpts = getU32(data,0x100)
        self.firstMetaBlockGroup = getU32(data,0x104) # used with meta bg feature
        self.mkfsTime = time.gmtime(getU32(data,0x108)) # fs creation date/time
        self.journalBlocks = [] # backup copy of journal inodes and sizes in last 2 elements
        for i in range(0,17):
            self.journalBlocks.append(getU32(data,0x10c + i*4))

        self.totalBlockGroups = self.blockGroups()
        self.blockCountHi= getU32(data,0x150)
        self.reservedBlockCountHi = getU32(data,0x154)
        self.freeBlockCountHi = getU32(data,0x158)
        self.minInodeExtraSize = getU16(data,0x15c) # min extra inode size to have
        self.wantExtraSize = getU16(data,0x15e) # new inodes need to have this much extra size
        self.miscFlags = getU32(data,0x160) # 1/2/4 signed hash /unsigned hash /testcode
        self.raidStride = getU16(data,0x164) 
        self.mmpInterval = getU16(data,0x166) # time between multi mount check , to prevent multi mount race condition
        self.mmpBlock = getU64(data,0x168) # block count for mmp data
        self.raidStrideWidth = getU32(data,0x170) 
        self.groupsPerFlex = pow(2 ,getU8(data,0x174))
        self.metadataCsumAlgoType = getU8(data,0x175) # only 1 crc32c
        self.reservedPad = getU16(data,0x176)
        self.kbytesWritten = getU64(data,0x178) #no of kbytes written in lifetime
        self.snapshotInum = getU32(data,0x180) # inode of snapshot (active)
        self.snapshotID = getU32(data,0x184)
        self.snapshotReservedBlocksCount = getU64(data,0x188)
        self.snapshotList = getU32(data,0x190) # inodes of th ehead of snapshot list on the disk
        self.errorCount = getU32(data,0x194) # number of errors seen till now
        self.firstErrorTime = time.gmtime(getU32(data,0x198))
        self.firstErrorInode = getU32(data,0x19c) # inodes involved in error
        self.firstErrorBlock = getU64(data,0x1a0) # num of block in first error
        self.firstErrorFunc = data[0x1a8:0x1c8].split(b'\x00')[0] # guilty function
        self.firstErrorLine = getU32(data,0x1c8)
        self.lastErrorTime = time.gmtime(getU32(data,0x1cc)) # latest error time
        self.lastErrorInode = getU32(data,0x1d0)
        self.lastErrorLine = getU32(data,0x1d4)
        self.lastErrorBlock = getU64(data,0x1d8)
        self.lastErrorFunc = data[0x1e0:0x200].split(b'\x00')[0]
        self.mountOptions = data[0x200:0x240].split(b'\x00')[0]
        self.userQuotaInode = getU32(data,0x240) # inode of user quota file
        self.groupQuotaInode = getU32(data,0x244) # same as above for group
        self.overheadBlocks = getU32(data,0x248) # always 0
        self.backupBGroups = [getU32(data,0x24c),getU32(data,0x250)] # super sparse only 
        self.encryptionAlgo = [getU8(data,0x254),getU8(data,0x255),getU8(data,0x256),getU8(data,0x257)]

        self.encryptPasswordSalt = []
        for i in range(0,16):
            self.encryptPasswordSalt.append(getU8(data,0x258 + i*1))
        self.lpfInfo = getU32(data,0x268) # inode of lost+found
        self.prjQuotaInode = getU32(data,0x26c)
        self.checksumSeed = getU32(data,0x270)
        self.upperWriteTime = getU8(data,0x274) 
        self.upperMountTime = getU8(data,0x275)
        self.upperMkfsTime = getU8(data,0x276)
        self.upperLastcheck = getU8(data,0x277)
        self.upperFirstErrorTime = getU8(data,0x278)
        self.upperLastErrorTime = getU8(data,0x279)
        self.zeroPad = [getU8(data,0x27a),getU8(data,0x27b)]
        self.fsCharsetEncoding = getU16(data,0x27c)
        self.fsCharsetEncodingFlags = getU16(data,0x27e)
        self.orphanFileInode = getU32(data,0x280)
        self.reserved = data[0x284:0x3fc]
        self.superBlockChecksum = getU32(data,0x3fc)

    def blockGroups(self):
    	bg = self.totalBlocks / self.blocksPerGroup
    	if(self.totalBlocks % self.blocksPerGroup != 0):
    		bg += 1
    	return bg

    def groupStartBlock(self,bgNo):
        return self.blocksPerGroup * bgNo
    
    def groupEndBlock(self,bgNo):
        return self.groupStartBlock(bgNo+1)-1 # as the start of next block group -1 will have an offset where previous blocks end

    def groupStartInode(self,bgNo):
        return self.inodesPerGroup * bgNo +1

    def groupEndInode(self,bgNo):
        return self.inodesPerGroup * (bgNo + 1)

    def groupFromBlock(self,blkno):
        return blkno // self.blocksPerGroup

    def groupIndexFromBlock(self,blkno):
        return blkno % self.blocksPerGroup

    def groupFromInode(self,inode):
        return (inode-1) // self.inodesPerGroup

    def groupIndexFromInode(self,inode):
        return (inode-1) % self.inodesPerGroup

    def hasSuperBlock(self,bgNo):
        if bgNo == 0:
            return True # as first block always has superblock
        retval = False

        if 'Sparse Super 2' in self.compatibleFeaturesList:
            if bgNo == self.backupBGroups[0] or bgNo == self.backupBGroups[1]:
                retval = True
        elif 'Sparse Superblock' in self.readOnlyCompatibleFeaturesList:
            retval = (bgNo == 1) or (bgNo == pow(3, round(log(bgNo) // log(3)))) or (bgNo == pow(5,round(log(bgNo) // log(5)))) or (bgNo == pow(7,round(log(bgNo) // log(7))))
            if retval:
                return retval
        elif 'Meta Block Groups' in self.incompatibleFeaturesList:
            if bgNo >= self.firstMetaBlockGroup:
                mbgsz = self.blockSize // 32
                retval = (bgNo % mbgsz == 0) or ((bgNo + 1) % mbgsz == 0) or ((bgNo + 2) % mbgsz == 0)
        else:
            retval = True
        return retval





    def printState(self):
        state = "unknown"
        if self.state == 0x1:
            state = 'Cleanly Unmounted'
        elif self.state == 0x2:
            state = 'Errors Detected'
        elif self.state == 0x4:
            state = 'Orphan inodes being recovered'

        return state

    def printErrorBehaviour(self):
        error = 'unknown'
        errornum = [1,2,3]
        errormean = ['Continue','Remount Read-Only','Panic']

        if self.errors in errornum:
            error = errormean[errornum.index(self.errors)]

        return error

    def printCreator(self):
        os = 'unknown'
        osnum = [0,1,2,3,4]
        osname = ['Linux','Hurd','Masix','FreeBSD','Lites']

        if self.creatorOS in osnum:
            os = osname[osnum.index(self.creatorOS)]
        return os

    def printHashAlgorithm(self):
        algo = 'unknown'
        algonum = [0,1,2,3,4,5]
        algoname = ['Legacy','Half MD4','Tea','Unsigned Legacy','Unsigned Half MD4','Unsigned Tea']

        if self.hashVersion in algonum:
            algo = algoname[algonum.index(self.hashVersion)]
        
        return algo

    def printEncryptionAlgorithm(self):
        enclist = []
        encnum = [1,2,3]
        encname = ['256bit AES-XTS','256bit AES-GCM','256bit AES-CBC']

        for v in self.encryptionAlgo:
            if v == 0:
                pass
            if v in encnum:
                enclist.append( encname[encnum.index(v)] )

        return enclist

    def groupDescriptorSize(self):
        if '64bit' in self.incompatibleFeaturesList:
            return 64
        else:
            return 32

    def prettyPrint(self):
        for key,value in self.__dict__.items():
            if key == 'mountTime' or key == 'writeTime' or key == 'lastcheck' or key == 'mkfsTime' or key == 'firstErrorTime' or key == 'lastErrorTime':
                print(f'{key} : {time.asctime(value)}')
            elif key == 'state':
                print(f'{key} : {self.printState()}')
            elif key == 'errors':
                print(f'{key} : {self.printErrorBehaviour()}')
            elif key == 'volumeUUID' or key == 'journalUUID':
                print(f'{key} : {printUuid(value)}')
            elif key == 'createrOS':
                print(f'{key} : {self.printCreator()}')
            elif key == 'hashVersion':
                print(f'{key} : {self.printHashAlgorithm()}')
            elif key == 'encryptionAlgo':
                print(f'{key} : {self.printEncryptionAlgorithm()}')
            elif key == 'reserved':
                pass
            else:
                print(f'{key} : {value}')


class GroupDescriptor():
    def __init__(self,data,wide=False):
        self.wide = wide
        self.blockBitmapLo=getU32(data)         #/* Blocks bitmap block */
        self.inodeBitmapLo=getU32(data, 4)      #/* Inodes bitmap block */
        self.inodeTableLo=getU32(data, 8)       #/* Inodes table block */
        self.freeBlocksCountLo=getU16(data, 0xc)#/* Free blocks count */
        self.freeInodesCountLo=getU16(data, 0xe)#/* Free inodes count */
        self.usedDirsCountLo=getU16(data, 0x10) #/* Directories count */
        self.flags=getU16(data, 0x12)           #/* EXT4_BG_flags (INODE_UNINIT, etc) */
        self.flagsList = self.printFlagList()
        self.excludeBitmapLo=getU32(data, 0x14)   #/* Exclude bitmap for snapshots */
        self.blockBitmapCsumLo=getU16(data, 0x18) #/* crc32c(s_uuid+grp_num+bbitmap) LE */
        self.inodeBitmapCsumLo=getU16(data, 0x1a) #/* crc32c(s_uuid+grp_num+ibitmap) LE */
        self.itableUnusedLo=getU16(data, 0x1c)  #/* Unused inodes count */
        self.checksum=getU16(data, 0x1e)                #/* crc16(sb_uuid+group+desc) */
        if wide==True:          
          self.blockBitmapHi=getU32(data, 0x20) #/* Blocks bitmap block MSB */
          self.inodeBitmapHi=getU32(data, 0x24) #/* Inodes bitmap block MSB */
          self.inodeTableHi=getU32(data, 0x28)  #/* Inodes table block MSB */
          self.freeBlocksCountHi=getU16(data, 0x2c) #/* Free blocks count MSB */
          self.freeInodesCountHi=getU16(data, 0x2e) #/* Free inodes count MSB */
          self.usedDirsCountHi=getU16(data, 0x30)       #/* Directories count MSB */
          self.itableUnusedHi=getU16(data, 0x32)    #/* Unused inodes count MSB */
          self.excludeBitmapHi=getU32(data, 0x34)   #/* Exclude bitmap block MSB */
          self.blockBitmapCsumHi=getU16(data, 0x38)#/* crc32c(s_uuid+grp_num+bbitmap) BE */
          self.inodeBitmapCsumHi=getU16(data, 0x3a)#/* crc32c(s_uuid+grp_num+ibitmap) BE */
          self.reserved=getU32(data, 0x3c)



    def printFlagList(self):
        flaglist = []
        if self.flags & 0x1:
            flaglist.append("Inode Uninitialized")
        if self.flags & 0x2:
            flaglist.append("Bitmap Uninitialized")
        if self.flags & 0x4:
            flaglist.append("Inode zeroed")
        return flaglist

    def prettyPrint(self):
        for key,value in self.__dict__.items():
            print(f"{key} : {value}")

class ExtGroupDescriptor():
    def __init__(self,bgd,sb,bgNo):
        self.blockGroup = bgNo
        self.startBlock = sb.groupStartBlock(bgNo)
        self.endBlock = sb.groupEndBlock(bgNo)
        self.startInode = sb.groupStartInode(bgNo)
        self.endInode = sb.groupEndInode(bgNo)
        self.flags = bgd.printFlagList()
        self.freeInodes = bgd.freeInodesCountLo
        if bgd.wide:
            self.freeInodes += bgd.freeInodesCountHi * pow(2,16)
        self.freeBlocks = bgd.freeBlocksCountLo
        if bgd.wide:
            self.freeBlocks += bgd.freeBlocksCountHi * pow(2,16)
        self.directories = bgd.usedDirsCountLo
        if bgd.wide:
            self.directories += bgd.usedDirsCountHi * pow(2,16)
        self.blockBitmapChecksum = bgd.blockBitmapCsumLo
        if bgd.wide:
            self.blockBitmapChecksum += bgd.blockBitmapCsumHi * pow(2,16)
        self.inodeBitmapChecksum = bgd.inodeBitmapCsumLo
        if bgd.wide:
            self.inodeBitmapChecksum += bgd.inodeBitmapCsumHi * pow(2,16) 

        self.checksum = bgd.checksum
        self.layout = []
        self.nonDataBlocks = 0
        
        fbgAdj = 1
        if 'Flexible Block Groups' in sb.incompatibleFeaturesList:
            if bgNo % sb.groupsPerFlex == 0:
                fbgAdj = sb.groupsPerFlex
        if sb.hasSuperBlock(bgNo):
            self.layout.append([ 'SuperBlock',self.startBlock,self.startBlock ])
            gdSize = sb.blockSize // int(sb.groupDescriptorSize() * sb.blockGroups())# // sb.blockSize)
            self.layout.append([ 'Group Descriptor Table' , self.startBlock + 1 , self.startBlock + gdSize ])
            self.nonDataBlocks += gdSize +1
            
            if sb.reservedGDTBlocks > 0:
                self.layout.append([ 'Reserved GDT Blocks',self.startBlock + gdSize + 1 , self.startBlock + gdSize + sb.reservedGDTBlocks ])
                self.nonDataBlocks += sb.reservedGDTBlocks

        bbm = bgd.blockBitmapLo
        if bgd.wide:
            bbm += bgd.blockBitmapHi * pow(2,32)

        self.layout.append( [ 'Data Block bitmap' , bbm,bbm ] )

        if sb.groupFromBlock(bbm) == bgNo:
            self.nonDataBlocks += fbgAdj


        ibm = bgd.inodeBitmapLo
        if bgd.wide:
            ibm += bgd.inodeBitmapHi * pow(2,32)

        self.layout.append( [ 'Inode bitmap' , ibm,ibm ] )

        if sb.groupFromBlock(ibm) == bgNo:
            self.nonDataBlocks += fbgAdj



        it = bgd.inodeTableLo
        if bgd.wide:
            it += bgd.inodeTableHi * pow(2,32)
        itBlocks = (sb.inodesPerGroup * sb.inodeSize) // sb.blockSize
        self.layout.append( [ 'Inode Table' , it,it + itBlocks - 1] )

        self.it = it

        if sb.groupFromBlock(it) == bgNo:
            self.nonDataBlocks += itBlocks * fbgAdj
        self.layout.append([ 'Data Blocks' , self.startBlock + self.nonDataBlocks , self.endBlock])

    def prettyPrint(self):
        print(f'\nBlock Group: {self.blockGroup}')
        print(f'Flags: {self.flags}')
        print(f'Blocks: {self.startBlock} - {self.endBlock}')
        print(f'Inodes: {self.startInode} - {self.endInode}')
        print(f'Layout:')
        for item in self.layout:
            print(f'\t{item[0]} {item[1]} - {item[2]}')

        print(f'Free Inodes: {self.freeInodes}')
        print(f'Free Blocks: {self.freeBlocks}')
        print(f'Directories: {self.directories}')
        print(f'Checksum: {hex(self.checksum)}')
        print(f'Block Bitmap Checksum: {hex(self.blockBitmapChecksum)}')
        print(f'Inode Bitmap Checksum: {hex(self.inodeBitmapChecksum)}')

class ExtMetaData():
    def __init__(self,image,offset):
        self.offset = offset
        self.image = image
        
        if not os.path.isfile(image):
            print(f"Image : {image} can't be read")
        
        with open(image,'rb') as f:
            f.seek(1024+ offset*512)
            sb = f.read(1024)

        
            self.superblock = SuperBlock(sb)

            if (self.superblock.magicSig != 0xef53):
                print(f'[!!] Wait a minute , this is not an ext2/3/4 fs , it\'s something else ')
                sys.exit(1)


            self.blockGroups = int(self.superblock.blockGroups())
    
            if(self.superblock.groupDescriptorSz != 0):
                self.wideBlockGroups = True
                self.blockGroupDescriptorSize = 64
            else:
                self.wideBlockGroups = False
                self.blockGroupDescriptorSize = 32
        
            #with open(self.image,'rb') as f:
            f.seek(offset*512 + 2*self.superblock.blockSize)
            bgdRaw = f.read(self.blockGroups * self.blockGroupDescriptorSize)
        
        self.bgdlist = []
        for i in range(0,self.blockGroups):
            bgd = GroupDescriptor(bgdRaw[i*self.blockGroupDescriptorSize:],self.wideBlockGroups) 
            ebgd = ExtGroupDescriptor(bgd,self.superblock,i)
            self.bgdlist.append(ebgd)

    def prettyPrint(self):
        self.superblock.prettyPrint()
        print(f"Total Block Groups : {self.blockGroups}")
        i = 0
        for bgd in self.bgdlist :
            bgd.prettyPrint()
            i += 1


def main():
    parser = argparse.ArgumentParser(description="Simple python script to check the superblock and prints its info of ext2/3/4 fs on mbr disks")
    parser.add_argument('-i','--image',type=str,required=True,help="Image to read the superblock from")
    parser.add_argument('-o','--offset',type=int,default=None,help="Start offset of the partition")
    parser.add_argument('-l','--listpartition',action='store_true',help="List all the partitions")
    parser.add_argument('-lsup','--listsuper',action='store_true',help="List the superblock info of the offset supplied")

    args = parser.parse_args()
    image = args.image

    extPart = [0x05,0x0f,0x85,0x91,0x9b,0xc5,0xe4]
    swp = [0x42,0x82,0xb8,0xc3,0xfc]
    
    
    if not os.path.isfile(image):
        print(f"Image : {image} can't be read")
        sys.exit(1)

    with open(image,'rb') as f:
        mbr = f.read(1024) #now we will get the mbr 

    logentry = []

    if(mbr[510] == 0x55 and mbr[511] == 0xaa and mbr[512:520] != b'EFI PART'):
        print("Looks like MBR or VBR")
        offset = 446 # this is start offset of the metadata of the partitions , 446 b is size of boot code
        mbr = mbr[:512] # snipping back to 512 b
        if( (hex(mbr[offset]) == '0x80' or hex(mbr[offset]) == '0x0') and \
            (hex(mbr[offset+16]) == '0x80' or hex(mbr[offset+16]) == '0x0') and \
            (hex(mbr[offset+32]) == '0x80' or hex(mbr[offset+32]) == '0x0') and \
            (hex(mbr[offset+48]) == '0x80' or hex(mbr[offset+48]) == '0x0')):
            print("Must be a MBR partition table disk")
            parts = [MBR(mbr,0,0,0),MBR(mbr,1,0,0),MBR(mbr,2,0,0),MBR(mbr,3,0,0)] # in mbr only 4 partition may exist or some logical partition needs to be there
            
            extlist = []

            for p in parts:
                if p.type in swp:
                    print(f"Swap Partition found at : {p.start}")
                    print(f"Superblock are only found in filesystems , not in swap partitions ")
                    continue

                if not p.empty:
                    if p.type in extPart:
                        print(f"Some logical/extended partitions are found at offset : {p.start}")
                        # generally only 1st and 2nd part is used as xtended partition , or there can be more extended in any of these two
                        bottomOfRabbitHole = False
                        logentry = [p.start]
                        i = 0
                        extpartno = 5
                        while not bottomOfRabbitHole:
                            with open(image,'rb') as f:
                                f.seek(logentry[i]*512)
                                llmbr = f.read(512)
                                            
                            llpart = [MBR(llmbr,0,1,extpartno),MBR(llmbr,1,1,-1)] # it should not be 5 or 6 as a new mbr is used to store these logical partitions so we use 0 and 1
                            if(llpart[1].type == 0):
                                extlist.append(llpart[0])
                            else:
                                extlist.extend(llpart)

                                # these extended partition are mapped dependent on the depth of logical part with relative to the offset of the original physical partition that stores the logical ones , we can access it by physical.partition.start  + logical.partition.start * 512
                         #       if not llpart[0].empty:
                          #          parts.append(llpart[0])
                            if llpart[0].type in swp:
                                print(f"Some logical/extended partition found at offset : {llpart[0].start}")
                            if llpart[1].type == 0:
                                bottomOfRabbitHole = True
                                print("No more partition left")
                            else:
                                logentry.append(logentry[i]+llpart[0].start+llpart[0].sector)
                                i+=1
                                extpartno += 1


        # now all the partitions including the physical and logical ones are in the list we created above
        # now getting the superblock info based on the partition we want or all the partition's superblock
        
        # checking for logical partition entry start for future purposes
        log_part = 0
        for i in range(len(parts)):
            if parts[i].type == 0x5: # if type of the partition is 5 in the main physical set then
                log_part = parts[i].start

        bak_extlist = extlist

        for i in (extlist): # doing because extlist also contains partition with type 0x5 and we only want the partition that are meaningful (linux/ntfs , etc) nothing else
            if i.type in extPart:
                extlist.remove(i)

        print("Logical/Extended Partitions Starts from : ",log_part)

        if(args.listpartition):
            printpart(parts)
            if len(extlist) != 0:
                print("Extended Partition Info Starts From Here : ")
                printpart(extlist)
        

        bak_logentry = logentry

        for i in range(len(logentry)):
            logentry[i] = logentry[i]+2048 # start offset of each extended partition

        startoffsettable = []
        for i in range(len(parts)):
            if parts[i].type not in extPart:
                if(not parts[i].empty):
                    startoffsettable.append(parts[i].start)

        for i in logentry:
            startoffsettable.append(i)
        


        # creating a dictionary that will store all the partition with a file system that are ext2/3/4
        typeofpart = []
        for i in startoffsettable:
            with open(image,'rb') as f:
                f.seek(1024+i*512)
                sb = f.read(60)

            if binascii.hexlify(sb[56:58]) == b'53ef':
                typeofpart.append('ext fs')
            else:
                typeofpart.append('unknown / not ext')

        partinfo = dict(zip(startoffsettable,typeofpart))
        partinfo = json.dumps(partinfo,indent=4)
        print("Starting offset of each available partition and their type: ")
        print(partinfo)
        offset_inext = 0
        
        if(args.offset):
            offset = args.offset
            if len(logentry)>0 and (offset >= logentry[0] and offset <= logentry[len(logentry)-1]):
                offset_inext = 1

                try:
                    partno = logentry.index(offset)
                except:
                    print(f"Offset {offset} is not an valid offset in the logical partitions, give a valid one ")
                    sys.exit(1)

            elif offset >= startoffsettable[0] and offset <= startoffsettable[:len(parts)-1][2]:
                
                try:
                    partno = startoffsettable.index(offset)
                except:
                    print(f"Offset {offset} is not valid offset in physical partitions , give a valid one")
                    sys.exit(1)

            else:
                print(f"Offset is either very low or very high of the current image : \n\t run fdisk -l {image} to get the start offset or of any partition")
                sys.exit(1)

        # till now we have offset , offsettable of all the partition , now we can get the superblock from the offset or all partition by (-lsup) option



        if(args.offset):
            print(f'Offset {args.offset} is of partition number : {partno+1}')
        if(args.listsuper and args.offset):
            print(f'\n\n[+] Listing superblock info of partition no. {partno+1} :')

            sb = ExtMetaData(image,offset)
            sb.prettyPrint()

        elif(args.listsuper):
            print(f'[!] Printing all partitions superblock , can be a lot of data , please specify an offset displayed above !!!')
            
    else:
        print("Must be a GPT partition , this program only works on MBR partition table disk or disk images")
        # offset = args.offset

        # with open(image,'rb') as f:
        #     f.seek(1024)
        #     p = f.read(128*128)

        # parts = []
        # startarray = []
        # namearray = []

        # for i in range(0,128):
        #     prt = GptRecord(p,i)
        #     if not prt.empty:
        #         parts.append(prt)
        #         startarray.append(prt.firstLBA)
        #         namearray.append(prt.partName.decode('latin-1'))

        
        # print(f"There are total {len(parts)} partitions on this image")
        # extParts = []
        # for i in parts:
        #     if i.partType == extguid:
        #         namearray[startarray.index(i.firstLBA)] = i.partName.decode('latin-1') + '/ ext2/3/4 fs'
        #         extParts.append(i)
       
        # dct = dict(zip(startarray,namearray))
        # dct = json.dumps(dct,indent=4)
        # print(dct)

        # if(args.listsuper and args.offset):
            # sb = ExtMetaData(image,offset)
            # sb.prettyPrint()


if __name__ == '__main__':
    main()
