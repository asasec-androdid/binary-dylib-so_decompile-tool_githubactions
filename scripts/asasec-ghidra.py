# -*- coding: utf-8 -*-
# Ghidra Moduler API Yonetici Betigi
# Aktif etmek istedigin ozelligin basindaki '#' isaretini kaldirabilirsin.

# hizli_dump //Bu ozellik hizli modda sadece temel verileri isler
dump_all_strings //binary icerisindeki tum stringleri disari aktarir
dump_functions //binary icerisindeki tum fonksiyon adlarini ve baslangic adreslerini kaydeder
dump_objc_classes //Tum Objective-C sinif adlarini ve metotlarini kaydeder
dump_xrefs //Kritik fonksiyonlarin çapraz referanslarini listeler
dump_imports_exports //Disa aktarilan ve disaridan alinan sembolleri kaydeder
find_string_references //Stringlerin hangi adreslerde gectigini eslestirir
dump_segments //segment ve section adres araliklarini listeler

import sys
from ghidra.program.model.listing import CodeUnit

def check_feature(script_path, name):
    try:
        with open(script_path, "r") as f:
            for line in f:
                stripped = line.strip()
                if name in stripped and not stripped.startswith("#"):
                    return True
    except:
        pass
    return False

def main():
    script_path = __file__
    import os
    out_dir = "/tmp/ghidra_out"
    
    print("[-] Ghidra Gelişmiş API Otomasyonu Başlatıldı...")

    # 1. String Dökümü
    if check_feature(script_path, "dump_all_strings"):
        print("[+] 'dump_all_strings' aktif: Stringler taranıyor...")
        listing = currentProgram.getListing()
        data_iter = listing.getData(True)
        count = 0
        with open(out_dir + "/strings.txt", "w") as f:
            while data_iter.hasNext():
                data = data_iter.next()
                dt = data.getDataType()
                if "string" in dt.getName().lower():
                    val = data.getValue()
                    if val:
                        f.write(f"{data.getMinAddress()}: {val}\n")
                        count += 1
        print(f"[+] {count} string kaydedildi.")

    # 2. Fonksiyon Dökümü
    if check_feature(script_path, "dump_functions"):
        print("[+] 'dump_functions' aktif: Fonksiyonlar taranıyor...")
        funcs = currentProgram.getFunctionManager().getFunctions(True)
        count = 0
        with open(out_dir + "/functions.txt", "w") as f:
            for fn in funcs:
                f.write(f"{fn.getEntryPoint()} -> {fn.getName()}\n")
                count += 1
        print(f"[+] {count} fonksiyon kaydedildi.")

    # 3. Objective-C Sınıf ve Metot Listesi (Yeni)
    if check_feature(script_path, "dump_objc_classes"):
        print("[+] 'dump_objc_classes' aktif: Objective-C sınıfları taranıyor...")
        # Ghidra simge tablosundan Objective-C namespace veya sembollerini yakalama
        symbol_table = currentProgram.getSymbolTable()
        symbols = symbol_table.getAllSymbols(True)
        count = 0
        with open(out_dir + "/objc_classes.txt", "w") as f:
            for sym in symbols:
                name = sym.getName()
                # Objective-C metot veya sınıf kalıplarını filtrele
                if name.startswith("-[") or name.startswith("+[") or "OBJC_CLASS_$" in name:
                    f.write(f"{sym.getAddress()} -> {name}\n")
                    count += 1
        print(f"[+] {count} Objective-C öğesi kaydedildi.")

    # 4. Çapraz Referanslar / Xref Dökümü (Yeni)
    if check_feature(script_path, "dump_xrefs"):
        print("[+] 'dump_xrefs' aktif: Fonksiyon Xref'leri taranıyor...")
        ref_manager = currentProgram.getReferenceManager()
        funcs = currentProgram.getFunctionManager().getFunctions(True)
        count = 0
        with open(out_dir + "/function_xrefs.txt", "w") as f:
            for fn in funcs:
                entry = fn.getEntryPoint()
                refs = ref_manager.getReferencesTo(entry)
                ref_list = [str(r.getFromAddress()) for r in refs]
                if ref_list:
                    f.write(f"{entry} ({fn.getName()}) <- Çağrılan yerler: {', '.join(ref_list)}\n")
                    count += 1
        print(f"[+] {count} fonksiyonun referansları kaydedildi.")

    # 5. Import / Export Sembolleri (Yeni)
    if check_feature(script_path, "dump_imports_exports"):
        print("[+] 'dump_imports_exports' aktif: Dış ve iç semboller taranıyor...")
        external_locs = currentProgram.getExternalManager().getExternalLocations()
        count = 0
        with open(out_dir + "/imports_exports.txt", "w") as f:
            for ext in external_locs:
                f.write(f"Import/Export: {ext.getLabel()} -> {ext.getAddress()}\n")
                count += 1
        print(f"[+] {count} dış sembol kaydedildi.")

    # 6. String Referans Avcısı (Yeni)
    if check_feature(script_path, "find_string_references"):
        print("[+] 'find_string_references' aktif: Stringlerin kod içi bağlantıları taranıyor...")
        listing = currentProgram.getListing()
        ref_manager = currentProgram.getReferenceManager()
        data_iter = listing.getData(True)
        count = 0
        with open(out_dir + "/string_references.txt", "w") as f:
            while data_iter.hasNext():
                data = data_iter.next()
                if "string" in data.getDataType().getName().lower():
                    val = data.getValue()
                    if val:
                        addr = data.getMinAddress()
                        refs = ref_manager.getReferencesTo(addr)
                        for r in refs:
                            f.write(f"String '{val}' ({addr}) -> Çağıran adres: {r.getFromAddress()}\n")
                            count += 1
        print(f"[+] {count} adet string referansı eşleştirildi.")

    # 7. Segment ve Section Listeleme
    if check_feature(script_path, "dump_segments"):
        print("[+] 'dump_segments' aktif: Segmentler listeleniyor...")
        blocks = currentProgram.getMemory().getBlocks()
        count = 0
        with open(out_dir + "/segments.txt", "w") as f:
            for b in blocks:
                f.write(f"Segment: {b.getName()} | Start: {b.getStart()} | End: {b.getEnd()}\n")
                count += 1
        print(f"[+] {count} segment kaydedildi.")

    print("[*] Tüm seçilen modüller başarıyla tamamlandı!")

if __name__ == "__main__":
    main()
