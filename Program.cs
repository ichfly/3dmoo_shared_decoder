using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Linq;
using System.Net;


namespace _3dmoo_shared_decoder
{

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct SAVE
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x4)]
        public char[] Magic;

        public uint MagicPadding;
        public ulong Unknown1;
        public ulong PartitionSize;
        public uint PartitionMediaSize;
        public ulong Unknown3;
        public uint Unknown4;
        public ulong FolderMapOffset;
        public uint FolderMapSize;
        public uint FolderMapMediaSize;
        public ulong FileMapOffset;
        public uint FileMapSize;
        public uint FileMapMediaSize;
        public ulong BlockMapOffset;
        public uint BlockMapSize;
        public uint BlockMapMediaSize;
        public ulong FileStoreOffset;
        public uint FileStoreLength;
        public uint FileStoreMedia;
        public uint FolderTableOffset;
        public uint FolderTableLength;
        public uint FolderTableUnknown;
        public uint FolderTableMedia;
        public uint FSTOffset;
        public uint FSTLength;
        public uint FSTUnknown;
        public uint FSTMedia;
    }


    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct DIFI
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x4)]
        public char[] Magic;
        public uint MagicPadding;
        public ulong IVFCOffset;
        public ulong IVFCSize;
        public ulong DPFSOffset;
        public ulong DPFSSize;
        public ulong HashOffset;
        public ulong HashSize;
        public uint Flags;
        public ulong FileBase;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct SaveFlashBlockMapEntry
    {
        public uint StartBlock;
        public uint EndBlock;
    }


    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IVFC
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x4)]
        public char[] Magic;
        public uint MagicPadding;
        public ulong Unknown1;

        public ulong FirstHashOffset;
        public ulong FirstHashLength;
        public ulong FirstHashBlock;
        public ulong SecondHashOffset;
        public ulong SecondHashLength;
        public ulong SecondHashBlock;

        public ulong HashTableOffset;
        public ulong HashTableLength;
        public ulong HashTableBlock;
        public ulong FileSystemOffset;
        public ulong FileSystemLength;
        public ulong FileSystemBlock;
        public ulong Unknown3; //0x78
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct DPFS
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x4)]
        public char[] Magic;
        public uint MagicPadding;

        public ulong FirstTableOffset;
        public ulong FirstTableLength;
        public ulong FirstTableBlock;
        public ulong SecondTableOffset;
        public ulong SecondTableLength;
        public ulong SecondTableBlock;
        public ulong OffsetToData;
        public ulong DataLength;
        public ulong DataBlock;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct FileSystemFolderEntry
    {
        public uint ParentFolderIndex;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)]
        public char[] FolderName;
        public uint Index;
        public uint Unknown1;
        public uint LastFileIndex;
        public uint Unknown2;
        public uint Unknown3;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct FileSystemFileEntry
    {
        public uint ParentFolderIndex;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)]
        public char[] Filename;
        public uint Index;
        public uint Magic;
        public uint BlockOffset;
        public ulong FileSize;
        public uint Unknown2; // flags and/or date?
        public uint Unknown3;
    }



    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct DISA
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x4)]
        public char[] Magic;
        public uint Unknown0;
        public ulong TableSize;
        public ulong PrimaryTableOffset;
        public ulong SecondaryTableOffset;
        public ulong TableLength;
        public ulong SAVEEntryOffset;
        public ulong SAVEEntryLength;
        public ulong DATAEntryOffset;
        public ulong DATAEntryLength;
        public ulong SAVEPartitionOffset;
        public ulong SAVEPartitionLength;
        public ulong DATAPartitionOffset;
        public ulong DATAPartitionLength;

        public uint ActiveTable;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x20)]
        public byte[] Hash;

        public uint ZeroPad0;
        public uint Flag0;
        public uint Unknown1;
        public uint ZeroPad1;
        public uint Unknown2; //Magic
        public ulong DataFsLength; //Why??
        public ulong Unknown3;
        public uint Unknown4;
        public uint Unknown5;
        public uint Unknown6;
        public uint Unknown7;
        public uint Unknown8;
        public uint Flag1;
        public uint Flag2;
        public uint Flag3;
        public uint Flag4;
        public uint Unknown14;
        public uint Flag5;
        public uint Unknown16;
        public uint Magic17;
        public uint Unknown18;
        public uint Flag6;
        public uint Flag7;
        public uint Flag8;
        public uint Unknown21;
        public uint Unknown22;
        public uint Unknown23;
    }

    class Program
    {
        public enum Sizes
        {
            SHA256 = 0x20,
            SHA512 = 0x40,
            SHA1 = 0x10,
            MD5 = 0x10,
            CRC16 = 0x02
        }
        static class MarshalUtil
        {
            public static byte[] StructureToByteArray<T>(T structure) where T : struct
            {
                var size = Marshal.SizeOf(structure);
                var byteArray = new byte[size];
                var pointer = Marshal.AllocHGlobal(size);
                Marshal.StructureToPtr(structure, pointer, false);
                Marshal.Copy(pointer, byteArray, 0, size);
                Marshal.FreeHGlobal(pointer);
                return byteArray;
            }
            public static T ReadStruct<T>(Stream fs)
            {
                var buffer = new byte[Marshal.SizeOf(typeof(T))];
                fs.Read(buffer, 0, Marshal.SizeOf(typeof(T)));
                var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                var temp = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
                handle.Free();
                return temp;
            }
            public static T ReadStructBE<T>(Stream fs)
            {
                var buffer = new byte[Marshal.SizeOf(typeof(T))];
                fs.Read(buffer, 0, Marshal.SizeOf(typeof(T)));
                var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                var typedObject = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
                handle.Free();
                var type = typedObject.GetType();
                var fieldInfo = type.GetFields();
                var typedReference = TypedReference.MakeTypedReference(typedObject, fieldInfo);
                foreach (var fi in fieldInfo)
                {
                    if (fi.FieldType == typeof(Int16))
                    {
                        var i16 = (Int16)fi.GetValue(typedObject);
                        var b16 = BitConverter.GetBytes(i16);
                        var b16R = b16.Reverse().ToArray();
                        fi.SetValueDirect(typedReference, BitConverter.ToInt16(b16R, 0));
                    }
                    else if (fi.FieldType == typeof(Int32))
                    {
                        var i32 = (Int32)fi.GetValue(typedObject);
                        var b32 = BitConverter.GetBytes(i32);
                        var b32R = b32.Reverse().ToArray();
                        fi.SetValueDirect(typedReference, BitConverter.ToInt32(b32R, 0));
                    }
                    else if (fi.FieldType == typeof(Int64))
                    {
                        var i64 = (Int64)fi.GetValue(typedObject);
                        var b64 = BitConverter.GetBytes(i64);
                        var b64R = b64.Reverse().ToArray();
                        fi.SetValueDirect(typedReference, BitConverter.ToInt64(b64R, 0));
                    }
                    else if (fi.FieldType == typeof(UInt16))
                    {
                        var i16 = (UInt16)fi.GetValue(typedObject);
                        var b16 = BitConverter.GetBytes(i16);
                        var b16R = b16.Reverse().ToArray();
                        fi.SetValueDirect(typedReference, BitConverter.ToUInt16(b16R, 0));
                    }
                    else if (fi.FieldType == typeof(UInt32))
                    {
                        var i32 = (UInt32)fi.GetValue(typedObject);
                        var b32 = BitConverter.GetBytes(i32);
                        var b32R = b32.Reverse().ToArray();
                        fi.SetValueDirect(typedReference, BitConverter.ToUInt32(b32R, 0));
                    }
                    else if (fi.FieldType == typeof(UInt64))
                    {
                        var i64 = (UInt64)fi.GetValue(typedObject);
                        var b64 = BitConverter.GetBytes(i64);
                        var b64R = b64.Reverse().ToArray();
                        fi.SetValueDirect(typedReference, BitConverter.ToUInt64(b64R, 0));
                    }
                }
                return typedObject;
            }

            private static bool IsSaveMagic(char[] buf)
            {
                return (buf[0] == 'S' && buf[1] == 'A' && buf[2] == 'V' && buf[3] == 'E');
            }

            private static bool IsDisaMagic(IList<char> buf)
            {
                return (buf[0] == 'D' && buf[1] == 'I' && buf[2] == 'S' && buf[3] == 'A');
            }

            private static uint ReadUInt32(Stream fs)
            {
                var buffer = new byte[4];
                fs.Read(buffer, 0, 4);
                return BitConverter.ToUInt32(buffer, 0);
            }


            public static string CharArrayToString(char[] array)
            {
                int i;
                var arraystring = string.Empty;
                for (i = 0; i < array.Length; i++)
                {
                    if (array[i] == 0) break;
                    arraystring += array[i];
                }
                return arraystring + "";
            }

            static string getpath(UInt32 id,ref FileSystemFolderEntry[] folder)
            {
                string temp = "";
                UInt32 iid = id;
                while(iid != 0)
                {
                    temp = temp + CharArrayToString(folder[iid - 1].FolderName) + "/";
                    iid = folder[iid - 1].ParentFolderIndex;
                }
                

                return temp;
            }

            static void Main(string[] args)
            {

                Console.WriteLine("Den Schmerz, den sie empfindet, wenn sie jemanden begegnet, kann sie nur lindern, indem sie ihn weitergibt. Statt einer Träne, muss es Blut sein, das fließt.");
                string[] filePaths1 = Directory.GetDirectories(args[0]);
                if (args.Length != 2)
                {
                    Console.WriteLine("Useage 3dmoodecoder.exe <<path to NANDUMP>/data/<hexnumbers>/sysdata/> <path to target folder>");
                }
                foreach (string s1 in filePaths1)
                {
                    string[] filePaths2 = Directory.GetDirectories(s1);
#if notdefined
                foreach(string s2 in filePaths2)
                {
#endif
                    string[] spli = { "\\", "/" };
                    string[] spliters1 = s1.Split(spli, StringSplitOptions.None);
#if notdefined
                    string[] spliters2 = s2.Split(spli, StringSplitOptions.None);                    
                    string targetpath = args[1] + "/" + "00000000" + spliters1[spliters1.Length - 1] + spliters2[spliters2.Length - 1] + "/";
#else
                    string targetpath = args[1] + "/" + spliters1[spliters1.Length - 1] + "00000000/";
#endif
                    Directory.CreateDirectory(targetpath);
#if notdefined
                    string[] filePaths3 = Directory.GetFiles(s2);
#else
                    string[] filePaths3 = Directory.GetFiles(s1);
#endif
                    foreach (string s3 in filePaths3)
                    {
                        FileStream fs = new FileStream(s3, FileMode.Open);
                        fs.Seek(0x100, SeekOrigin.Begin);
                        DISA Disa;
                        Disa = MarshalUtil.ReadStruct<DISA>(fs);
                        if (!IsDisaMagic(Disa.Magic))
                        {
                            Console.WriteLine("DISA not found\n");
                            fs.Close();
                            continue;
                        }
                        //Which table to read
                        if ((Disa.ActiveTable & 1) == 1) //second table
                            fs.Seek((long)Disa.PrimaryTableOffset, SeekOrigin.Begin);
                        else
                            fs.Seek((long)Disa.SecondaryTableOffset, SeekOrigin.Begin);
                        if(Disa.TableSize != 1)
                        {
                            Console.WriteLine("Disa.TableSize is " + Disa.TableSize.ToString() + "\n");
                            fs.Close();
                            continue;
                        }
                        DIFI Difi = MarshalUtil.ReadStruct<DIFI>(fs);
                        IVFC Ivfc = MarshalUtil.ReadStruct<IVFC>(fs);
                        DPFS Dpfs = MarshalUtil.ReadStruct<DPFS>(fs);
                        fs.Seek((long)Disa.SAVEPartitionOffset, SeekOrigin.Begin);


                        ulong OffsetInImage = (ulong)fs.Position;

                        fs.Seek((long)Dpfs.FirstTableOffset, SeekOrigin.Current);
                        UInt32 FirstFlag = ReadUInt32(fs);
                        UInt32 FirstFlagDupe = ReadUInt32(fs);
                        UInt32 SecondFlag = ReadUInt32(fs);
                        fs.Seek((long)Dpfs.SecondTableLength - 4, SeekOrigin.Current);
                        UInt32 UInt32SecondFlagDupe = ReadUInt32(fs);


                        fs.Seek((long)(OffsetInImage + Dpfs.OffsetToData), SeekOrigin.Begin);

                        //jump to dupe if needed (SAVE partition is written twice)
                        /*if ((SecondFlag & 0x20000000) == 0) //*** EXPERIMENTAL ***
                            fs.Seek((long)Dpfs.DataLength, SeekOrigin.Current);*/

                        fs.Seek((long)Ivfc.FileSystemOffset, SeekOrigin.Current);


                        UInt32 saveOffset = (UInt32)fs.Position;
                        SAVE Save = MarshalUtil.ReadStruct<SAVE>(fs);
                        //add SAVE information (if exists) (suppose to...)
                        if (IsSaveMagic(Save.Magic)) //read
                        {
                            fs.Seek(saveOffset + (long)Save.FileMapOffset, SeekOrigin.Begin);
                            uint[] FilesMap = new uint[Save.FileMapSize];
                            for (int i = 0; i < FilesMap.Length; i++)
                                FilesMap[i] = ReadUInt32(fs);
                            fs.Seek(saveOffset + (long)Save.FolderMapOffset, SeekOrigin.Begin);
                            uint[] FoldersMap = new uint[Save.FolderMapSize];
                            for (int i = 0; i < FoldersMap.Length; i++)
                                FoldersMap[i] = ReadUInt32(fs);
                            fs.Seek(saveOffset + (long)Save.BlockMapOffset, SeekOrigin.Begin);
                            var first = MarshalUtil.ReadStruct<SaveFlashBlockMapEntry>(fs);
                            SaveFlashBlockMapEntry[] BlockMap = new SaveFlashBlockMapEntry[first.EndBlock + 2];
                            BlockMap[0] = first;
                            for (uint i = 1; i < BlockMap.Length; i++)
                                BlockMap[i] = MarshalUtil.ReadStruct<SaveFlashBlockMapEntry>(fs);

                            //-- Get folders -- (and set filebase 'while at it')
                            /*if (!IsData)
                            {*/
                                long FileBase = saveOffset + (long)Save.FileStoreOffset;
                                fs.Seek(FileBase + Save.FolderTableOffset * 0x1000, SeekOrigin.Begin);
                            /*}
                            else
                            {   //file base is remote
                                FileBase = (long)(Disa.DATAPartitionOffset + Partitions[1].Difi.FileBase);
                                fs.Seek(saveOffset + Save.FolderTableOffset, SeekOrigin.Begin);
                            }*/
                            var froot = MarshalUtil.ReadStruct<FileSystemFolderEntry>(fs);
                            FileSystemFolderEntry[] Folders = new FileSystemFolderEntry[froot.ParentFolderIndex - 1];
                            if (froot.ParentFolderIndex > 1) //if has folders
                                for (int i = 0; i < Folders.Length; i++)
                                    Folders[i] = MarshalUtil.ReadStruct<FileSystemFolderEntry>(fs);

                            //-- Get files --
                            //go to FST
                            //if (!IsData)
                                fs.Seek(FileBase + Save.FSTOffset * 0x1000, SeekOrigin.Begin); //this is different
                            /*else //file base is remote
                                fs.Seek(saveOffset + Save.FSTOffset, SeekOrigin.Begin);*/

                            var root = MarshalUtil.ReadStruct<FileSystemFileEntry>(fs);
                            if (root.ParentFolderIndex != 0)
                            {
                                if ((root.ParentFolderIndex > 1) && (root.Magic == 0))
                                    for (int i = 0; i < root.ParentFolderIndex - 1; i++)
                                    {
                                        try //some contain garbage
                                        {
                                            FileSystemFileEntry File = MarshalUtil.ReadStruct<FileSystemFileEntry>(fs);

                                            byte[] fileBuffer = new byte[File.FileSize];
                                            long temp = fs.Position;
                                            fs.Seek((FileBase + File.BlockOffset * 0x1000), SeekOrigin.Begin);
                                            fs.Read(fileBuffer, 0, fileBuffer.Length);
                                            Directory.CreateDirectory(targetpath + getpath(File.ParentFolderIndex, ref Folders));
                                            FileStream fsout = new FileStream(targetpath + getpath(File.ParentFolderIndex, ref Folders) + CharArrayToString(File.Filename), FileMode.Create);
                                            fsout.Write(fileBuffer, 0, fileBuffer.Length);
                                            fs.Position = temp;
                                            fsout.Close();
                                        }
                                        catch
                                        {
                                            Console.WriteLine("error in file " + s3.ToString());
                                        }
                                    }
                            }
                            else
                            {
                                Console.WriteLine("error in root");
                            }
                        }
                        else
                        {   //Not a legal SAVE filesystem
                            Console.WriteLine("not a legal SAVE filesystem\n");
                        }


                        fs.Close();
                    }
                }
                Console.WriteLine("3dmoo extract finished");
            }
        }
    }
}
