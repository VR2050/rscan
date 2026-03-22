package net.sourceforge.pinyin4j;

import java.io.FileNotFoundException;
import java.io.IOException;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p295o.p296a.p297a.C2675c;
import p005b.p295o.p296a.p297a.C2682j;

/* loaded from: classes3.dex */
public class PinyinRomanizationResource {
    private C2675c pinyinMappingDoc;

    public static class PinyinRomanizationSystemResourceHolder {
        public static final PinyinRomanizationResource theInstance = new PinyinRomanizationResource();

        private PinyinRomanizationSystemResourceHolder() {
        }
    }

    public static PinyinRomanizationResource getInstance() {
        return PinyinRomanizationSystemResourceHolder.theInstance;
    }

    private void initializeResource() {
        try {
            setPinyinMappingDoc(C2354n.m2487j1("", ResourceHelper.getResourceInputStream("/pinyindb/pinyin_mapping.xml")));
        } catch (C2682j e2) {
            e2.printStackTrace();
        } catch (FileNotFoundException e3) {
            e3.printStackTrace();
        } catch (IOException e4) {
            e4.printStackTrace();
        }
    }

    private void setPinyinMappingDoc(C2675c c2675c) {
        this.pinyinMappingDoc = c2675c;
    }

    public C2675c getPinyinMappingDoc() {
        return this.pinyinMappingDoc;
    }

    private PinyinRomanizationResource() {
        initializeResource();
    }
}
