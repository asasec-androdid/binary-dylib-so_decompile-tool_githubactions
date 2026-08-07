# -*- coding: utf-8 -*-

# Ghidra Moduler API Yonetici Betigi
# Aktif etmek istedigin ozelligin onune True yaz. Kapatmak icin False yaz.

dump_all_strings = True       # Binary icerisindeki tum stringleri disari aktarir
dump_functions = True         # Tum fonksiyon adlarini ve baslangic adreslerini kaydeder
dump_objc_classes = False     # Tum Objective-C sinif adlarini ve metotlarini kaydeder
dump_xrefs = True             # Kritik fonksiyonlarin capraz referanslarini listeler
dump_imports_exports = True   # Disa aktarilan ve disaridan alinan sembolleri kaydeder
find_string_references = True # Stringlerin kod ici baglantilarini eslestirir
dump_segments = True          # Segment ve section adres araliklarini listeler

############################################################################################

import sys
import os
import codecs
from ghidra.program.model.listing import CodeUnit

def main():
    out_dir = "/tmp/ghidra_out"
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    
    print("[-] Ghidra Gelismis API Otomasyonu Baslatildi...")

    # 1. String Dokumu
    if dump_all_strings:
        print("[+] 'dump_all_strings' aktif: Stringler taranıyor...")
        listing = currentProgram.getListing()
        data_iter = listing.getData(True)
        count = 0
        with codecs.open(out_dir + "/strings.txt", "w", encoding="utf-8") as f:
            while data_iter.hasNext():
                data = data_iter.next()
                dt = data.getDataType()
                if "string" in dt.getName().lower():
                    val = data.getValue()
                    if val:
                        try:
                            f.write(str(data.getMinAddress()) + ": " + unicode(val) + "\n")
                            count += 1
                        except:
                            pass
        print("[+] " + str(count) + " string kaydedildi.")

    # 2. Fonksiyon Dokumu
    if dump_functions:
        print("[+] 'dump_functions' aktif: Fonksiyonlar taranıyor...")
        funcs = currentProgram.getFunctionManager().getFunctions(True)
        count = 0
        with codecs.open(out_dir + "/functions.txt", "w", encoding="utf-8") as f:
            for fn in funcs:
                f.write(str(fn.getEntryPoint()) + " -> " + str(fn.getName()) + "\n")
                count += 1
        print("[+] " + str(count) + " fonksiyon kaydedildi.")

    # 3. Objective-C Sinif ve Metot Listesi
    if dump_objc_classes:
        print("[+] 'dump_objc_classes' aktif: Objective-C siniflari taranıyor...")
        symbol_table = currentProgram.getSymbolTable()
        symbols = symbol_table.getAllSymbols(True)
        count = 0
        with codecs.open(out_dir + "/objc_classes.txt", "w", encoding="utf-8") as f:
            for sym in symbols:
                name = sym.getName()
                if name.startswith("-[") or name.startswith("+[") or "OBJC_CLASS_$" in name:
                    f.write(str(sym.getAddress()) + " -> " + str(name) + "\n")
                    count += 1
        print("[+] " + str(count) + " Objective-C ogesi kaydedildi.")

    # 4. Capraz Referanslar / Xref Dokumu
    if dump_xrefs:
        print("[+] 'dump_xrefs' aktif: Fonksiyon Xref'leri taranıyor...")
        ref_manager = currentProgram.getReferenceManager()
        funcs = currentProgram.getFunctionManager().getFunctions(True)
        count = 0
        with codecs.open(out_dir + "/function_xrefs.txt", "w", encoding="utf-8") as f:
            for fn in funcs:
                entry = fn.getEntryPoint()
                refs = ref_manager.getReferencesTo(entry)
                ref_list = [str(r.getFromAddress()) for r in refs]
                if ref_list:
                    f.write(str(entry) + " (" + str(fn.getName()) + ") <- Cagrildigi yerler: " + ", ".join(ref_list) + "\n")
                    count += 1
        print("[+] " + str(count) + " fonksiyonun referanslari kaydedildi.")

    # 5. Import / Export Sembolleri
    if dump_imports_exports:
        print("[+] 'dump_imports_exports' aktif: Dis ve ic semboller taranıyor...")
        external_locs = currentProgram.getExternalManager().getExternalLocations()
        count = 0
        with codecs.open(out_dir + "/imports_exports.txt", "w", encoding="utf-8") as f:
            for ext in external_locs:
                f.write("Import/Export: " + str(ext.getLabel()) + " -> " + str(ext.getAddress()) + "\n")
                count += 1
        print("[+] " + str(count) + " dis sembol kaydedildi.")

    # 6. String Referans Avcisi
    if find_string_references:
        print("[+] 'find_string_references' aktif: Stringlerin kod ici baglantilari taranıyor...")
        listing = currentProgram.getListing()
        ref_manager = currentProgram.getReferenceManager()
        data_iter = listing.getData(True)
        count = 0
        with codecs.open(out_dir + "/string_references.txt", "w", encoding="utf-8") as f:
            while data_iter.hasNext():
                data = data_iter.next()
                if "string" in data.getDataType().getName().lower():
                    val = data.getValue()
                    if val:
                        addr = data.getMinAddress()
                        refs = ref_manager.getReferencesTo(addr)
                        for r in refs:
                            try:
                                f.write("String '" + unicode(val) + "' (" + str(addr) + ") -> Cagiran adres: " + str(r.getFromAddress()) + "\n")
                                count += 1
                            except:
                                pass
        print("[+] " + str(count) + " adet string referansi eslestirildi.")

    # 7. Segment ve Section Listeleme
    if dump_segments:
        print("[+] 'dump_segments' aktif: Segmentler listeleniyor...")
        blocks = currentProgram.getMemory().getBlocks()
        count = 0
        with codecs.open(out_dir + "/segments.txt", "w", encoding="utf-8") as f:
            for b in blocks:
                f.write("Segment: " + str(b.getName()) + " | Start: " + str(b.getStart()) + " | End: " + str(b.getEnd()) + "\n")
                count += 1
        print("[+] " + str(count) + " segment kaydedildi.")

    print("[*] Tum secilen moduller basariyla tamamlandi!")

if __name__ == "__main__":
    main()
