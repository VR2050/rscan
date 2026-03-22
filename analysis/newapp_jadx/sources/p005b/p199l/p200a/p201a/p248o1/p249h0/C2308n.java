package p005b.p199l.p200a.p201a.p248o1.p249h0;

import android.content.ContentValues;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.util.SparseArray;
import android.util.SparseBooleanArray;
import androidx.annotation.Nullable;
import androidx.annotation.WorkerThread;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p203b1.C1937a;
import p005b.p199l.p200a.p201a.p203b1.InterfaceC1938b;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2345e;
import p005b.p199l.p200a.p201a.p250p1.C2363w;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.o1.h0.n */
/* loaded from: classes.dex */
public class C2308n {

    /* renamed from: a */
    public final HashMap<String, C2307m> f5875a;

    /* renamed from: b */
    public final SparseArray<String> f5876b;

    /* renamed from: c */
    public final SparseBooleanArray f5877c;

    /* renamed from: d */
    public final SparseBooleanArray f5878d;

    /* renamed from: e */
    public c f5879e;

    /* renamed from: f */
    @Nullable
    public c f5880f;

    /* renamed from: b.l.a.a.o1.h0.n$a */
    public static final class a implements c {

        /* renamed from: a */
        public static final String[] f5881a = {"id", "key", "metadata"};

        /* renamed from: b */
        public final InterfaceC1938b f5882b;

        /* renamed from: c */
        public final SparseArray<C2307m> f5883c = new SparseArray<>();

        /* renamed from: d */
        public String f5884d;

        /* renamed from: e */
        public String f5885e;

        public a(InterfaceC1938b interfaceC1938b) {
            this.f5882b = interfaceC1938b;
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n.c
        /* renamed from: a */
        public void mo2236a() {
            InterfaceC1938b interfaceC1938b = this.f5882b;
            String str = this.f5884d;
            try {
                String str2 = "ExoPlayerCacheIndex" + str;
                SQLiteDatabase writableDatabase = interfaceC1938b.getWritableDatabase();
                writableDatabase.beginTransactionNonExclusive();
                try {
                    try {
                        if (C4195m.m4776K0(writableDatabase, "ExoPlayerVersions")) {
                            writableDatabase.delete("ExoPlayerVersions", "feature = ? AND instance_uid = ?", new String[]{Integer.toString(1), str});
                        }
                        writableDatabase.execSQL("DROP TABLE IF EXISTS " + str2);
                        writableDatabase.setTransactionSuccessful();
                    } finally {
                        writableDatabase.endTransaction();
                    }
                } catch (SQLException e2) {
                    throw new C1937a(e2);
                }
            } catch (SQLException e3) {
                throw new C1937a(e3);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n.c
        /* renamed from: b */
        public void mo2237b(C2307m c2307m, boolean z) {
            if (z) {
                this.f5883c.delete(c2307m.f5870a);
            } else {
                this.f5883c.put(c2307m.f5870a, null);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n.c
        /* renamed from: c */
        public void mo2238c(HashMap<String, C2307m> hashMap) {
            try {
                SQLiteDatabase writableDatabase = this.f5882b.getWritableDatabase();
                writableDatabase.beginTransactionNonExclusive();
                try {
                    m2245j(writableDatabase);
                    Iterator<C2307m> it = hashMap.values().iterator();
                    while (it.hasNext()) {
                        m2244i(writableDatabase, it.next());
                    }
                    writableDatabase.setTransactionSuccessful();
                    this.f5883c.clear();
                } finally {
                    writableDatabase.endTransaction();
                }
            } catch (SQLException e2) {
                throw new C1937a(e2);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n.c
        /* renamed from: d */
        public void mo2239d(C2307m c2307m) {
            this.f5883c.put(c2307m.f5870a, c2307m);
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n.c
        /* renamed from: e */
        public boolean mo2240e() {
            return C4195m.m4815k0(this.f5882b.getReadableDatabase(), 1, this.f5884d) != -1;
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n.c
        /* renamed from: f */
        public void mo2241f(HashMap<String, C2307m> hashMap) {
            if (this.f5883c.size() == 0) {
                return;
            }
            try {
                SQLiteDatabase writableDatabase = this.f5882b.getWritableDatabase();
                writableDatabase.beginTransactionNonExclusive();
                for (int i2 = 0; i2 < this.f5883c.size(); i2++) {
                    try {
                        C2307m valueAt = this.f5883c.valueAt(i2);
                        if (valueAt == null) {
                            writableDatabase.delete(this.f5885e, "id = ?", new String[]{Integer.toString(this.f5883c.keyAt(i2))});
                        } else {
                            m2244i(writableDatabase, valueAt);
                        }
                    } catch (Throwable th) {
                        writableDatabase.endTransaction();
                        throw th;
                    }
                }
                writableDatabase.setTransactionSuccessful();
                this.f5883c.clear();
                writableDatabase.endTransaction();
            } catch (SQLException e2) {
                throw new C1937a(e2);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n.c
        /* renamed from: g */
        public void mo2242g(long j2) {
            String hexString = Long.toHexString(j2);
            this.f5884d = hexString;
            this.f5885e = C1499a.m637w("ExoPlayerCacheIndex", hexString);
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n.c
        /* renamed from: h */
        public void mo2243h(HashMap<String, C2307m> hashMap, SparseArray<String> sparseArray) {
            C4195m.m4771I(this.f5883c.size() == 0);
            try {
                if (C4195m.m4815k0(this.f5882b.getReadableDatabase(), 1, this.f5884d) != 1) {
                    SQLiteDatabase writableDatabase = this.f5882b.getWritableDatabase();
                    writableDatabase.beginTransactionNonExclusive();
                    try {
                        m2245j(writableDatabase);
                        writableDatabase.setTransactionSuccessful();
                        writableDatabase.endTransaction();
                    } catch (Throwable th) {
                        writableDatabase.endTransaction();
                        throw th;
                    }
                }
                Cursor query = this.f5882b.getReadableDatabase().query(this.f5885e, f5881a, null, null, null, null, null);
                while (query.moveToNext()) {
                    try {
                        int i2 = query.getInt(0);
                        String string = query.getString(1);
                        hashMap.put(string, new C2307m(i2, string, C2308n.m2229a(new DataInputStream(new ByteArrayInputStream(query.getBlob(2))))));
                        sparseArray.put(i2, string);
                    } finally {
                    }
                }
                query.close();
            } catch (SQLiteException e2) {
                hashMap.clear();
                sparseArray.clear();
                throw new C1937a(e2);
            }
        }

        /* renamed from: i */
        public final void m2244i(SQLiteDatabase sQLiteDatabase, C2307m c2307m) {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            C2308n.m2230b(c2307m.f5873d, new DataOutputStream(byteArrayOutputStream));
            byte[] byteArray = byteArrayOutputStream.toByteArray();
            ContentValues contentValues = new ContentValues();
            contentValues.put("id", Integer.valueOf(c2307m.f5870a));
            contentValues.put("key", c2307m.f5871b);
            contentValues.put("metadata", byteArray);
            sQLiteDatabase.replaceOrThrow(this.f5885e, null, contentValues);
        }

        /* renamed from: j */
        public final void m2245j(SQLiteDatabase sQLiteDatabase) {
            C4195m.m4772I0(sQLiteDatabase, 1, this.f5884d, 1);
            sQLiteDatabase.execSQL("DROP TABLE IF EXISTS " + this.f5885e);
            sQLiteDatabase.execSQL("CREATE TABLE " + this.f5885e + " (id INTEGER PRIMARY KEY NOT NULL,key TEXT NOT NULL,metadata BLOB NOT NULL)");
        }
    }

    /* renamed from: b.l.a.a.o1.h0.n$b */
    public static class b implements c {

        /* renamed from: a */
        public final boolean f5886a;

        /* renamed from: b */
        @Nullable
        public final Cipher f5887b;

        /* renamed from: c */
        @Nullable
        public final SecretKeySpec f5888c;

        /* renamed from: d */
        @Nullable
        public final Random f5889d;

        /* renamed from: e */
        public final C2345e f5890e;

        /* renamed from: f */
        public boolean f5891f;

        /* renamed from: g */
        @Nullable
        public C2363w f5892g;

        public b(File file, @Nullable byte[] bArr, boolean z) {
            Cipher cipher;
            SecretKeySpec secretKeySpec;
            if (bArr != null) {
                C4195m.m4765F(bArr.length == 16);
                try {
                    if (C2344d0.f6035a == 18) {
                        try {
                            cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING", "BC");
                        } catch (Throwable unused) {
                        }
                        secretKeySpec = new SecretKeySpec(bArr, "AES");
                    }
                    cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                    secretKeySpec = new SecretKeySpec(bArr, "AES");
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e2) {
                    throw new IllegalStateException(e2);
                }
            } else {
                C4195m.m4765F(!z);
                cipher = null;
                secretKeySpec = null;
            }
            this.f5886a = z;
            this.f5887b = cipher;
            this.f5888c = secretKeySpec;
            this.f5889d = z ? new Random() : null;
            this.f5890e = new C2345e(file);
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n.c
        /* renamed from: a */
        public void mo2236a() {
            C2345e c2345e = this.f5890e;
            c2345e.f6049a.delete();
            c2345e.f6050b.delete();
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n.c
        /* renamed from: b */
        public void mo2237b(C2307m c2307m, boolean z) {
            this.f5891f = true;
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n.c
        /* renamed from: c */
        public void mo2238c(HashMap<String, C2307m> hashMap) {
            DataOutputStream dataOutputStream = null;
            try {
                OutputStream m2351c = this.f5890e.m2351c();
                C2363w c2363w = this.f5892g;
                if (c2363w == null) {
                    this.f5892g = new C2363w(m2351c);
                } else {
                    c2363w.m2605b(m2351c);
                }
                DataOutputStream dataOutputStream2 = new DataOutputStream(this.f5892g);
                try {
                    dataOutputStream2.writeInt(2);
                    dataOutputStream2.writeInt(this.f5886a ? 1 : 0);
                    if (this.f5886a) {
                        byte[] bArr = new byte[16];
                        this.f5889d.nextBytes(bArr);
                        dataOutputStream2.write(bArr);
                        try {
                            this.f5887b.init(1, this.f5888c, new IvParameterSpec(bArr));
                            dataOutputStream2.flush();
                            dataOutputStream2 = new DataOutputStream(new CipherOutputStream(this.f5892g, this.f5887b));
                        } catch (InvalidAlgorithmParameterException e2) {
                            e = e2;
                            throw new IllegalStateException(e);
                        } catch (InvalidKeyException e3) {
                            e = e3;
                            throw new IllegalStateException(e);
                        }
                    }
                    dataOutputStream2.writeInt(hashMap.size());
                    int i2 = 0;
                    for (C2307m c2307m : hashMap.values()) {
                        dataOutputStream2.writeInt(c2307m.f5870a);
                        dataOutputStream2.writeUTF(c2307m.f5871b);
                        C2308n.m2230b(c2307m.f5873d, dataOutputStream2);
                        i2 += m2246i(c2307m, 2);
                    }
                    dataOutputStream2.writeInt(i2);
                    C2345e c2345e = this.f5890e;
                    Objects.requireNonNull(c2345e);
                    dataOutputStream2.close();
                    c2345e.f6050b.delete();
                    int i3 = C2344d0.f6035a;
                    this.f5891f = false;
                } catch (Throwable th) {
                    th = th;
                    dataOutputStream = dataOutputStream2;
                    int i4 = C2344d0.f6035a;
                    if (dataOutputStream != null) {
                        try {
                            dataOutputStream.close();
                        } catch (IOException unused) {
                        }
                    }
                    throw th;
                }
            } catch (Throwable th2) {
                th = th2;
            }
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n.c
        /* renamed from: d */
        public void mo2239d(C2307m c2307m) {
            this.f5891f = true;
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n.c
        /* renamed from: e */
        public boolean mo2240e() {
            return this.f5890e.m2349a();
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n.c
        /* renamed from: f */
        public void mo2241f(HashMap<String, C2307m> hashMap) {
            if (this.f5891f) {
                mo2238c(hashMap);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n.c
        /* renamed from: g */
        public void mo2242g(long j2) {
        }

        /* JADX WARN: Removed duplicated region for block: B:70:0x00c5  */
        /* JADX WARN: Removed duplicated region for block: B:72:? A[RETURN, SYNTHETIC] */
        @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n.c
        /* renamed from: h */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void mo2243h(java.util.HashMap<java.lang.String, p005b.p199l.p200a.p201a.p248o1.p249h0.C2307m> r11, android.util.SparseArray<java.lang.String> r12) {
            /*
                Method dump skipped, instructions count: 216
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n.b.mo2243h(java.util.HashMap, android.util.SparseArray):void");
        }

        /* renamed from: i */
        public final int m2246i(C2307m c2307m, int i2) {
            int hashCode = c2307m.f5871b.hashCode() + (c2307m.f5870a * 31);
            if (i2 >= 2) {
                return (hashCode * 31) + c2307m.f5873d.hashCode();
            }
            long m2248a = C2309o.m2248a(c2307m.f5873d);
            return (hashCode * 31) + ((int) (m2248a ^ (m2248a >>> 32)));
        }

        /* renamed from: j */
        public final C2307m m2247j(int i2, DataInputStream dataInputStream) {
            C2312r m2229a;
            int readInt = dataInputStream.readInt();
            String readUTF = dataInputStream.readUTF();
            if (i2 < 2) {
                long readLong = dataInputStream.readLong();
                C2311q c2311q = new C2311q();
                C2311q.m2249a(c2311q, readLong);
                m2229a = C2312r.f5895a.m2251a(c2311q);
            } else {
                m2229a = C2308n.m2229a(dataInputStream);
            }
            return new C2307m(readInt, readUTF, m2229a);
        }
    }

    /* renamed from: b.l.a.a.o1.h0.n$c */
    public interface c {
        /* renamed from: a */
        void mo2236a();

        /* renamed from: b */
        void mo2237b(C2307m c2307m, boolean z);

        /* renamed from: c */
        void mo2238c(HashMap<String, C2307m> hashMap);

        /* renamed from: d */
        void mo2239d(C2307m c2307m);

        /* renamed from: e */
        boolean mo2240e();

        /* renamed from: f */
        void mo2241f(HashMap<String, C2307m> hashMap);

        /* renamed from: g */
        void mo2242g(long j2);

        /* renamed from: h */
        void mo2243h(HashMap<String, C2307m> hashMap, SparseArray<String> sparseArray);
    }

    public C2308n(@Nullable InterfaceC1938b interfaceC1938b, @Nullable File file, @Nullable byte[] bArr, boolean z, boolean z2) {
        C4195m.m4771I((interfaceC1938b == null && file == null) ? false : true);
        this.f5875a = new HashMap<>();
        this.f5876b = new SparseArray<>();
        this.f5877c = new SparseBooleanArray();
        this.f5878d = new SparseBooleanArray();
        a aVar = interfaceC1938b != null ? new a(interfaceC1938b) : null;
        b bVar = file != null ? new b(new File(file, "cached_content_index.exi"), bArr, z) : null;
        if (aVar == null || (bVar != null && z2)) {
            this.f5879e = bVar;
            this.f5880f = aVar;
        } else {
            this.f5879e = aVar;
            this.f5880f = bVar;
        }
    }

    /* renamed from: a */
    public static C2312r m2229a(DataInputStream dataInputStream) {
        int readInt = dataInputStream.readInt();
        HashMap hashMap = new HashMap();
        for (int i2 = 0; i2 < readInt; i2++) {
            String readUTF = dataInputStream.readUTF();
            int readInt2 = dataInputStream.readInt();
            if (readInt2 < 0) {
                throw new IOException(C1499a.m626l("Invalid value size: ", readInt2));
            }
            int min = Math.min(readInt2, 10485760);
            byte[] bArr = C2344d0.f6040f;
            int i3 = 0;
            while (i3 != readInt2) {
                int i4 = i3 + min;
                bArr = Arrays.copyOf(bArr, i4);
                dataInputStream.readFully(bArr, i3, min);
                min = Math.min(readInt2 - i4, 10485760);
                i3 = i4;
            }
            hashMap.put(readUTF, bArr);
        }
        return new C2312r(hashMap);
    }

    /* renamed from: b */
    public static void m2230b(C2312r c2312r, DataOutputStream dataOutputStream) {
        Set<Map.Entry<String, byte[]>> entrySet = c2312r.f5897c.entrySet();
        dataOutputStream.writeInt(entrySet.size());
        for (Map.Entry<String, byte[]> entry : entrySet) {
            dataOutputStream.writeUTF(entry.getKey());
            byte[] value = entry.getValue();
            dataOutputStream.writeInt(value.length);
            dataOutputStream.write(value);
        }
    }

    /* renamed from: c */
    public C2307m m2231c(String str) {
        return this.f5875a.get(str);
    }

    /* renamed from: d */
    public C2307m m2232d(String str) {
        C2307m c2307m = this.f5875a.get(str);
        if (c2307m != null) {
            return c2307m;
        }
        SparseArray<String> sparseArray = this.f5876b;
        int size = sparseArray.size();
        int i2 = 0;
        int keyAt = size == 0 ? 0 : sparseArray.keyAt(size - 1) + 1;
        if (keyAt < 0) {
            while (i2 < size && i2 == sparseArray.keyAt(i2)) {
                i2++;
            }
            keyAt = i2;
        }
        C2307m c2307m2 = new C2307m(keyAt, str, C2312r.f5895a);
        this.f5875a.put(str, c2307m2);
        this.f5876b.put(keyAt, str);
        this.f5878d.put(keyAt, true);
        this.f5879e.mo2239d(c2307m2);
        return c2307m2;
    }

    @WorkerThread
    /* renamed from: e */
    public void m2233e(long j2) {
        c cVar;
        this.f5879e.mo2242g(j2);
        c cVar2 = this.f5880f;
        if (cVar2 != null) {
            cVar2.mo2242g(j2);
        }
        if (this.f5879e.mo2240e() || (cVar = this.f5880f) == null || !cVar.mo2240e()) {
            this.f5879e.mo2243h(this.f5875a, this.f5876b);
        } else {
            this.f5880f.mo2243h(this.f5875a, this.f5876b);
            this.f5879e.mo2238c(this.f5875a);
        }
        c cVar3 = this.f5880f;
        if (cVar3 != null) {
            cVar3.mo2236a();
            this.f5880f = null;
        }
    }

    /* renamed from: f */
    public void m2234f(String str) {
        C2307m c2307m = this.f5875a.get(str);
        if (c2307m == null || !c2307m.f5872c.isEmpty() || c2307m.f5874e) {
            return;
        }
        this.f5875a.remove(str);
        int i2 = c2307m.f5870a;
        boolean z = this.f5878d.get(i2);
        this.f5879e.mo2237b(c2307m, z);
        if (z) {
            this.f5876b.remove(i2);
            this.f5878d.delete(i2);
        } else {
            this.f5876b.put(i2, null);
            this.f5877c.put(i2, true);
        }
    }

    @WorkerThread
    /* renamed from: g */
    public void m2235g() {
        this.f5879e.mo2241f(this.f5875a);
        int size = this.f5877c.size();
        for (int i2 = 0; i2 < size; i2++) {
            this.f5876b.remove(this.f5877c.keyAt(i2));
        }
        this.f5877c.clear();
        this.f5878d.clear();
    }
}
