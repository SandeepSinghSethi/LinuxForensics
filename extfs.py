#!/usr/bin/env python3

from superblockInfo import *
import calendar
import argparse


class ExtentHeader():
    def __init__(self,data):
        self.magic = getU16(data) # always 0xf30a
        self.entries = getU16(data,0x2)
        self.max = getU16(data,0x4)
        self.depth = getU16(data,0x6)
        self.generation = getU32(data,0x8)
        self.isExtent = False
    def prettyPrint(self):
        print(f"Extent Entries : {self.entries} , Max-Entries : {self.max} , Depth : {self.depth} , Gen : {self.generation}")

class ExtentIndex():
    def __init__(self,data):
        self.block = getU32(data)
        self.leafLo = getU32(data,0x4)
        self.leafHi = getU32(data,0x8)
        self.isExtent = False
    def prettyPrint(self):
        print(f"Index Block : {self.block} , Leaf : {self.leafHi * pow(2,32) + self.leafLo}")

class Extent():
    def __init__(self,data):
        self.block = getU32(data)
        self.len = getU16(data,0x4)
        self.startHi = getU16(data,0x6)
        self.startLo = getU32(data,0x8)
        self.addr = self.startHi*pow(2,32) + self.startLo
        self.isExtent = True
    def prettyPrint(self):
        print(f"Extent Block : {self.block} , Data Blocks : {self.startHi * pow(2,32) + self.startLo} - {self.len + (self.startHi * pow(2,32) + self.startLo - 1)} , Extent-Len : {self.len}")

def getInodeModes(mode):
    retval = []

    if mode & 0x1:
        retval.append('Others Exec')
    if mode & 0x2:
        retval.append('Others Write')
    if mode & 0x4:
        retval.append('Others Read')
    if mode & 0x8:
        retval.append('Group Exec')
    if mode & 0x10:
        retval.append('Group Write')
    if mode & 0x20:
        retval.append('Group Read')
    if mode & 0x40:
        retval.append('Owner Exec')
    if mode & 0x80:
        retval.append('Owner Write')
    if mode & 0x100:
        retval.append('Owner Read')
    if mode & 0x200:
        retval.append('Sticky Bit')
    if mode & 0x400:
        retval.append('Set GID')
    if mode & 0x800:
        retval.append('Set UID')

    return retval

def getInodeFileType(mode):
    mode = (mode & 0xf000) >> 12 # last 4 bits

    if mode == 0x1:
        return 'FIFO'
    elif mode == 0x2:
        return 'Char Device'
    elif mode == 0x4:
        return 'Directory'
    elif mode == 0x6:
        return 'Block Device'
    elif mode == 0x8:
        return 'Regular File'
    elif mode == 0xa:
        return 'SymLink'
    elif mode == 0xc:
        return 'Socket'
    else:
        return "Unknown FileType"

def getInodeFlags(flags):
    retval =[]
    
    if flags & 0x1:
        retval.append('Secure Deletion')
    if flags & 0x2:
        retval.append('Preserve For Undelete')
    if flags & 0x4:
        retval.append('File is Compressed')
    if flags & 0x8:
        retval.append('Synchronous Write')
    if flags & 0x10:
        retval.append('Immutable File')
    if flags & 0x20:
        retval.append('Append Only')
    if flags & 0x40:
        retval.append('No dump')
    if flags & 0x80:
        retval.append('Dont update access time')
    if flags & 0x100:
        retval.append('Dirty Compressed File')
    if flags & 0x200:
        retval.append('Compressed Clusters')
    if flags & 0x400:
        retval.append('Dont compress')
    if flags & 0x800:
        retval.append('Encrypted Inode')
    if flags & 0x1000:
        retval.append('Directory Has Hash Index')
    if flags & 0x2000:
        retval.append('AFS Magic Directory')
    if flags & 0x4000:
        retval.append('Must be written through journal')
    if flags & 0x8000:
        retval.append('File Tail not merged')
    if flags & 0x10000:
        retval.append('Directory Entry sync writes')
    if flags & 0x20000:
        retval.append('Top of directory')
    if flags & 0x40000:
        retval.append('Huge File')
    if flags & 0x80000:
        retval.append('Inode Uses Extents')
    if flags & 0x200000:
        retval.append('Large Extended Attributes in Inode')
    if flags & 0x400000:
        retval.append('Blocks Past EOF')
    if flags & 0x1000000:
        retval.append('Inode is Snapshot')
    if flags & 0x4000000:
        retval.append('Snapshot is being deleted')
    if flags & 0x8000000:
        retval.append('Snapshot Shrink Completed')
    if flags & 0x10000000:
        retval.append('Inline Data')
    if flags & 0x80000000:
        retval.append('Reserved For Ext4 Library')
    if flags & 0x4bdfff:
        retval.append('User-Visible Flags')
    if flags & 0x4b80ff:
        retval.append('User-Modifiable Flags')

    return retval

def getInodeLoc(inodeno,inodespergroup):
    bg = int((inodeno-1)) // int(inodespergroup)
    index = int(inodeno-1) % int(inodespergroup)
    return [bg,index]


def getExtentTree(data):
    retval = []
    retval.append(ExtentHeader(data))
    if retval[0].depth == 0: #leaf node
        for i in range(0,retval[0].entries):
            retval.append(Extent(data[(i+1)*12:]))
    else:
        for i in range(0,retval[0].entries):
            retval.append(ExtentIndex(data[(i+1)*12:]))

    return retval

class Inode():
    def __init__(self, data, inodeSize=128):
        self.mode = getU16(data)
        self.modeList = getInodeModes(self.mode)
        self.fileType = getInodeFileType(self.mode)
        self.ownerID = getU16(data, 0x2)
        self.fileSize = getU32(data, 0x4)
        self.accessTime = time.gmtime(getU32(data, 0x8))
        self.changeTime = time.gmtime(getU32(data, 0xC))
        self.modifyTime = time.gmtime(getU32(data, 0x10))
        self.deleteTime = time.gmtime(getU32(data, 0x14))
        self.groupID = getU16(data, 0x18)
        self.links = getU16(data, 0x1a)
        self.blocks = getU32(data, 0x1c)
        self.flags = getU32(data, 0x20)
        self.flagList = getInodeFlags(self.flags)
        self.osd1 = getU32(data, 0x24) # high 32-bits of generation for Linux
        self.block = []
        self.extents = []
        if self.flags & 0x80000:
            self.extents = getExtentTree(data[0x28 : ])
        else:
            for i in range(0, 15):
                self.block.append(getU32(data, 0x28 + i * 4))
        self.generation = getU32(data, 0x64)
        self.extendAttribs = getU32(data, 0x68)
        self.fileSize += pow(2, 32) * getU32(data, 0x6c)
        # these are technically only correct for Linux ext4 filesystems
        # should probably verify that that is the case
        self.blocks += getU16(data, 0x74) * pow(2, 32)
        self.extendAttribs += getU16(data, 0x76) * pow(2, 32)
        self.ownerID += getU16(data, 0x78) * pow(2, 32)
        self.groupID += getU16(data, 0x7a) * pow(2, 32)
        self.checksum = getU16(data, 0x7c)
        if inodeSize > 128:
            self.inodeSize = 128 + getU16(data, 0x80)
        if self.inodeSize > 0x82:
            self.checksum += getU16(data, 0x82) * pow(2, 16)
        if self.inodeSize > 0x84:
            self.changeTimeNanosecs = getU32(data, 0x84) >> 2
        if self.inodeSize > 0x88:
            self.modifyTimeNanosecs = getU32(data, 0x88) >> 2
        if self.inodeSize > 0x8c:
            self.accessTimeNanosecs = getU32(data, 0x8c) >> 2
        if self.inodeSize > 0x90:
            self.createTime = time.gmtime(getU32(data, 0x90))
            self.createTimeNanosecs = getU32(data, 0x94) >> 2
        else:
            self.createTime = time.gmtime(0)

    def prettyPrint(self):
        for k, v in (self.__dict__.items()) :
            if k == 'extents' and self.extents:
                v[0].prettyPrint() # print header
                for i in range(1, v[0].entries + 1):
                    v[i].prettyPrint()
            elif k == 'changeTime' or k == 'modifyTime' or k == 'accessTime' or k == 'createTime':
                print(k+":", time.asctime(v))
            elif k == 'deleteTime':
                if calendar.timegm(v) == 0:
                    print( 'Deleted: no')
                else:
                    print(k+":", time.asctime(v))
            else:
                print( k+":", v)

def getDataBlock(image,offset,block,blksize=4096):
    with open(image,'rb') as f:
        f.seek(block*blksize + 512*offset) # this will get you to your actual data in your disk try with xxd -s block*blksize + 512*offset and you will get your data
        data = f.read(blksize)
    return data


# now getting the actual data blocks from the inode blocks which can be found in inode metadata
def getBlockList(inode,image,offset,blksize=4096):
    datablock = []
    ext = []

    if inode.extents: # if blocks are contigous stored in a tree like structure
        if inode.extents[0].depth == 0:
            for i in range(1,inode.extents[0].entries+1):
                x = inode.extents[i]
                ext.append(x)
                start = x.startHi*pow(2,32) + x.startLo
                end = start + x.len
                for j in range(start,end):
                    datablock.append(j)
        else:
            currentLvl = inode.extents # saving for future
            leafnode = []
            # print('hii****************8i',currentLvl)
            # print(currentLvl[0].depth,currentLvl[1].block,currentLvl[1].leafLo,currentLvl[1].leafHi)
            while currentLvl[0].depth != 0:
                nextlvl = []
                print("entries : ",currentLvl[0].entries)
                for i in range(1,currentLvl[0].entries+1):
                    blkno = currentLvl[i].leafLo+ currentLvl[i].leafHi*pow(2,32)
                    currnode = getExtentTree(getDataBlock(image,offset,blkno,blksize))
                    nextlvl.extend(currnode) # because it's not a leaf node
                    if currnode[0].depth == 0:
                        leafnode.extend(currnode[1:])

                for i in nextlvl:
                	if i.isExtent:
                		ext.append(i)
                currentLvl = nextlvl

            # print("leafnode:",leafnode)
            leafnode.sort(key=lambda x: x.block)
            for leaf in leafnode:
                sb = leaf.startHi*pow(2,32) + leaf.startLo
                en = sb + leaf.len
                for j in range(sb,en):
                    datablock.append(j)
    
    else:
        blocks = inode.fileSize / blksize
        for i in range(0,12):
            datablock.append(inode.block[i])
            if i >= blocks:
                break

        if blocks > 12:
            iddata = getDataBlock(image,offset,inode.block[12],blksize)
            for i in range(0,blksize//4):
                idblock = getU32(iddata,i*4)
                if idblock == 0:
                    break
                else:
                    datablock.append(idblock)

        if blocks > (12 + blksize / 4):
            diddata = getDataBlock(image, offset, inode.block[13], blksize)
            for i in range(0, blksize / 4):
                didblock = getU32(diddata, i * 4)
                if didblock == 0:
                    break
                else:
                    iddata = getDataBlock(image, offset, didblock, blksize)
                    for j in range(0, blksize / 4):
                        idblock = getU32(iddata, j * 4)
                        if idblock == 0:
                            break
                        else:
                            datablock.append(idblock)

    # now triple indirect blocks
        if blocks > (12 + blksize / 4 + blksize * blksize / 16):
            tiddata = getDataBlock(image, offset, inode.block[14], blksize)
            for i in range(0, blksize / 4):
                tidblock = getU32(tiddata, i * 4)
                if tidblock == 0:
                    break
                else:
                    diddata = getDataBlock(image, offset, tidblock, blksize)
                    for j in range(0, blksize / 4):
                        didblock = getU32(diddata, j * 4)
                    if didblock == 0:
                        break
                    else:
                        iddata = getDataBlock(image, offset, didblock, blksize)
                        for k in range(0, blockSize / 4):
                            idblock = getU32(iddata, k * 4)
                            if idblock == 0:
                                break
                            else:
                                datablock.append(idblock)

    return (datablock,ext)

def printFileType(ftype):
    if ftype == 0x0 or ftype > 7:
        return "Unknown"
    elif ftype == 0x1:
        return "Regular"
    elif ftype == 0x2:
        return "Directory"
    elif ftype == 0x3:
        return "Character device"
    elif ftype == 0x4:
        return "Block device"
    elif ftype == 0x5:
        return "FIFO"
    elif ftype == 0x6:
        return "Socket"
    elif ftype == 0x7:
        return "Symbolic link"


class DirectoryEntry():
    def __init__(self,data):
        self.inode = getU32(data)
        self.recordlen = getU16(data,0x4)
        self.namelen = getU8(data,0x6)
        self.fileType = getU8(data,0x7)
        self.filename = data[0x8:0x8 + self.namelen]

    def prettyPrint(self):
        print(f"Inode : {self.inode} , FileType : {self.fileType} , Filename : {self.filename.decode()} , FileType : {printFileType(self.fileType)}")

def getDirectory(data):
	done = False

	retval = []
	i = 0
	while not done:
		de = DirectoryEntry(data[i:])
		if de.inode == 0:
			done = True
		else:
			retval.append(de)
			i += de.recordlen
		if i>=len(data):
			break
	return retval


def main():
    parser = argparse.ArgumentParser(description="Simple python script that prints info about the inode of a directory and lists all its files .")
    parser.add_argument('-i','--image',type=str,required=True,help="Image to read the superblock from")
    parser.add_argument('-o','--offset',type=int,required=True,default=None,help="Start offset of the partition")
    parser.add_argument('-n','--inode',type=int,required=True,default=None,help="Inode of the directory to list files from")
    # parser.add_argument('-w','--write',type=str,default=None,help="Write the content to an outfile")
    args = parser.parse_args()

    image = args.image
    offset = args.offset
    inode = args.inode

    emd = ExtMetaData(image,offset)
    inodeloc = getInodeLoc(inode,emd.superblock.inodesPerGroup)
    offinode = emd.bgdlist[inodeloc[0]].it*emd.superblock.blockSize + inodeloc[1]*emd.superblock.inodeSize
    print(emd.bgdlist[inodeloc[0]].it,offinode)
    with open(image,'rb') as f:
        f.seek(offinode + offset * 512)
        data = f.read(emd.superblock.inodeSize)

    inode = Inode(data,emd.superblock.inodeSize)
    print(inodeloc,offinode)
    inode.prettyPrint()
    
    datablk,extent = getBlockList(inode,image,offset,emd.superblock.blockSize)
    if inode.fileType != 'Directory' :
    	print(f"Inode is not of a directory !!")
    	sys.exit(1)

    # for i in extent:
    # 	print(f"->>> Offset : {((i.startLo) + i.startHi*pow(2,32))*emd.superblock.blockSize} , Length : {i.len*emd.superblock.blockSize}")
    # print(datablk)
    data = b""
    for db in datablk:
    	data += (getDataBlock(image,offset,db,emd.superblock.blockSize))
    # print(data,len(data))

    dir = getDirectory(data)
    for entry in dir:
        entry.prettyPrint()

if __name__ == '__main__':
    main()
