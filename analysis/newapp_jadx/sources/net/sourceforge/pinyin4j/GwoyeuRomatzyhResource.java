package net.sourceforge.pinyin4j;

import java.io.FileNotFoundException;
import java.io.IOException;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p295o.p296a.p297a.C2675c;
import p005b.p295o.p296a.p297a.C2682j;

/* loaded from: classes3.dex */
public class GwoyeuRomatzyhResource {
    private C2675c pinyinToGwoyeuMappingDoc;

    public static class GwoyeuRomatzyhSystemResourceHolder {
        public static final GwoyeuRomatzyhResource theInstance = new GwoyeuRomatzyhResource();

        private GwoyeuRomatzyhSystemResourceHolder() {
        }
    }

    public static GwoyeuRomatzyhResource getInstance() {
        return GwoyeuRomatzyhSystemResourceHolder.theInstance;
    }

    private void initializeResource() {
        try {
            setPinyinToGwoyeuMappingDoc(C2354n.m2487j1("", ResourceHelper.getResourceInputStream("/pinyindb/pinyin_gwoyeu_mapping.xml")));
        } catch (C2682j e2) {
            e2.printStackTrace();
        } catch (FileNotFoundException e3) {
            e3.printStackTrace();
        } catch (IOException e4) {
            e4.printStackTrace();
        }
    }

    private void setPinyinToGwoyeuMappingDoc(C2675c c2675c) {
        this.pinyinToGwoyeuMappingDoc = c2675c;
    }

    public C2675c getPinyinToGwoyeuMappingDoc() {
        return this.pinyinToGwoyeuMappingDoc;
    }

    private GwoyeuRomatzyhResource() {
        initializeResource();
    }
}
