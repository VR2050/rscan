package com.p397ta.utdid2.p400b.p401a;

import com.p397ta.utdid2.p400b.p401a.InterfaceC4139b;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.WeakHashMap;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: com.ta.utdid2.b.a.d */
/* loaded from: classes2.dex */
public class C4141d {

    /* renamed from: b */
    private static final Object f10829b = new Object();

    /* renamed from: a */
    private File f10830a;

    /* renamed from: a */
    private final Object f10831a = new Object();

    /* renamed from: a */
    private HashMap<File, a> f10832a = new HashMap<>();

    /* renamed from: com.ta.utdid2.b.a.d$a */
    public static final class a implements InterfaceC4139b {

        /* renamed from: c */
        private static final Object f10833c = new Object();

        /* renamed from: a */
        private Map f10834a;

        /* renamed from: a */
        private WeakHashMap<InterfaceC4139b.b, Object> f10835a;

        /* renamed from: b */
        private final File f10836b;

        /* renamed from: c */
        private final int f10837c;

        /* renamed from: c */
        private final File f10838c;

        /* renamed from: j */
        private boolean f10839j = false;

        public a(File file, int i2, Map map) {
            this.f10836b = file;
            this.f10838c = C4141d.m4684a(file);
            this.f10837c = i2;
            this.f10834a = map == null ? new HashMap() : map;
            this.f10835a = new WeakHashMap<>();
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* renamed from: e */
        public boolean m4694e() {
            if (this.f10836b.exists()) {
                if (this.f10838c.exists()) {
                    this.f10836b.delete();
                } else if (!this.f10836b.renameTo(this.f10838c)) {
                    return false;
                }
            }
            try {
                FileOutputStream m4690a = m4690a(this.f10836b);
                if (m4690a == null) {
                    return false;
                }
                C4142e.m4704a(this.f10834a, m4690a);
                m4690a.close();
                this.f10838c.delete();
                return true;
            } catch (Exception unused) {
                if (this.f10836b.exists()) {
                    this.f10836b.delete();
                }
                return false;
            }
        }

        @Override // com.p397ta.utdid2.p400b.p401a.InterfaceC4139b
        /* renamed from: b */
        public boolean mo4668b() {
            return this.f10836b != null && new File(this.f10836b.getAbsolutePath()).exists();
        }

        /* renamed from: d */
        public boolean m4697d() {
            boolean z;
            synchronized (this) {
                z = this.f10839j;
            }
            return z;
        }

        @Override // com.p397ta.utdid2.p400b.p401a.InterfaceC4139b
        public Map<String, ?> getAll() {
            HashMap hashMap;
            synchronized (this) {
                hashMap = new HashMap(this.f10834a);
            }
            return hashMap;
        }

        @Override // com.p397ta.utdid2.p400b.p401a.InterfaceC4139b
        public long getLong(String str, long j2) {
            synchronized (this) {
                Long l2 = (Long) this.f10834a.get(str);
                if (l2 != null) {
                    j2 = l2.longValue();
                }
            }
            return j2;
        }

        @Override // com.p397ta.utdid2.p400b.p401a.InterfaceC4139b
        public String getString(String str, String str2) {
            synchronized (this) {
                String str3 = (String) this.f10834a.get(str);
                if (str3 != null) {
                    str2 = str3;
                }
            }
            return str2;
        }

        /* renamed from: com.ta.utdid2.b.a.d$a$a, reason: collision with other inner class name */
        public final class C5127a implements InterfaceC4139b.a {

            /* renamed from: b */
            private final Map<String, Object> f10841b = new HashMap();

            /* renamed from: k */
            private boolean f10842k = false;

            public C5127a() {
            }

            @Override // com.p397ta.utdid2.p400b.p401a.InterfaceC4139b.a
            /* renamed from: a */
            public InterfaceC4139b.a mo4673a(String str, String str2) {
                synchronized (this) {
                    this.f10841b.put(str, str2);
                }
                return this;
            }

            @Override // com.p397ta.utdid2.p400b.p401a.InterfaceC4139b.a
            /* renamed from: b */
            public InterfaceC4139b.a mo4675b() {
                synchronized (this) {
                    this.f10842k = true;
                }
                return this;
            }

            @Override // com.p397ta.utdid2.p400b.p401a.InterfaceC4139b.a
            public boolean commit() {
                boolean z;
                ArrayList arrayList;
                HashSet<InterfaceC4139b.b> hashSet;
                boolean m4694e;
                synchronized (C4141d.f10829b) {
                    z = a.this.f10835a.size() > 0;
                    arrayList = null;
                    if (z) {
                        arrayList = new ArrayList();
                        hashSet = new HashSet(a.this.f10835a.keySet());
                    } else {
                        hashSet = null;
                    }
                    synchronized (this) {
                        if (this.f10842k) {
                            a.this.f10834a.clear();
                            this.f10842k = false;
                        }
                        for (Map.Entry<String, Object> entry : this.f10841b.entrySet()) {
                            String key = entry.getKey();
                            Object value = entry.getValue();
                            if (value == this) {
                                a.this.f10834a.remove(key);
                            } else {
                                a.this.f10834a.put(key, value);
                            }
                            if (z) {
                                arrayList.add(key);
                            }
                        }
                        this.f10841b.clear();
                    }
                    m4694e = a.this.m4694e();
                    if (m4694e) {
                        a.this.m4696a(true);
                    }
                }
                if (z) {
                    for (int size = arrayList.size() - 1; size >= 0; size--) {
                        String str = (String) arrayList.get(size);
                        for (InterfaceC4139b.b bVar : hashSet) {
                            if (bVar != null) {
                                bVar.m4676a(a.this, str);
                            }
                        }
                    }
                }
                return m4694e;
            }

            @Override // com.p397ta.utdid2.p400b.p401a.InterfaceC4139b.a
            /* renamed from: a */
            public InterfaceC4139b.a mo4671a(String str, int i2) {
                synchronized (this) {
                    this.f10841b.put(str, Integer.valueOf(i2));
                }
                return this;
            }

            @Override // com.p397ta.utdid2.p400b.p401a.InterfaceC4139b.a
            /* renamed from: a */
            public InterfaceC4139b.a mo4672a(String str, long j2) {
                synchronized (this) {
                    this.f10841b.put(str, Long.valueOf(j2));
                }
                return this;
            }

            @Override // com.p397ta.utdid2.p400b.p401a.InterfaceC4139b.a
            /* renamed from: a */
            public InterfaceC4139b.a mo4670a(String str, float f2) {
                synchronized (this) {
                    this.f10841b.put(str, Float.valueOf(f2));
                }
                return this;
            }

            @Override // com.p397ta.utdid2.p400b.p401a.InterfaceC4139b.a
            /* renamed from: a */
            public InterfaceC4139b.a mo4674a(String str, boolean z) {
                synchronized (this) {
                    this.f10841b.put(str, Boolean.valueOf(z));
                }
                return this;
            }

            @Override // com.p397ta.utdid2.p400b.p401a.InterfaceC4139b.a
            /* renamed from: a */
            public InterfaceC4139b.a mo4669a(String str) {
                synchronized (this) {
                    this.f10841b.put(str, this);
                }
                return this;
            }
        }

        /* renamed from: a */
        public void m4696a(boolean z) {
            synchronized (this) {
                this.f10839j = z;
            }
        }

        /* renamed from: a */
        public void m4695a(Map map) {
            if (map != null) {
                synchronized (this) {
                    this.f10834a = map;
                }
            }
        }

        @Override // com.p397ta.utdid2.p400b.p401a.InterfaceC4139b
        /* renamed from: a */
        public InterfaceC4139b.a mo4667a() {
            return new C5127a();
        }

        /* renamed from: a */
        private FileOutputStream m4690a(File file) {
            FileOutputStream fileOutputStream;
            try {
                fileOutputStream = new FileOutputStream(file);
            } catch (FileNotFoundException unused) {
                if (!file.getParentFile().mkdir()) {
                    return null;
                }
                try {
                    fileOutputStream = new FileOutputStream(file);
                } catch (FileNotFoundException unused2) {
                    return null;
                }
            }
            return fileOutputStream;
        }
    }

    public C4141d(String str) {
        if (str == null || str.length() <= 0) {
            throw new RuntimeException("Directory can not be empty");
        }
        this.f10830a = new File(str);
    }

    /* renamed from: a */
    private File m4685a(File file, String str) {
        if (str.indexOf(File.separatorChar) < 0) {
            return new File(file, str);
        }
        throw new IllegalArgumentException(C1499a.m639y("File ", str, " contains a path separator"));
    }

    /* renamed from: b */
    private File m4688b(String str) {
        return m4685a(m4683a(), C1499a.m637w(str, ".xml"));
    }

    /* renamed from: a */
    private File m4683a() {
        File file;
        synchronized (this.f10831a) {
            file = this.f10830a;
        }
        return file;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:37:0x008c A[Catch: all -> 0x005a, TRY_ENTER, TRY_LEAVE, TryCatch #15 {all -> 0x005a, blocks: (B:64:0x0057, B:37:0x008c), top: B:18:0x0035 }] */
    /* JADX WARN: Removed duplicated region for block: B:80:0x0093 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r0v10 */
    /* JADX WARN: Type inference failed for: r0v11 */
    /* JADX WARN: Type inference failed for: r0v12 */
    /* JADX WARN: Type inference failed for: r0v14 */
    /* JADX WARN: Type inference failed for: r0v15 */
    /* JADX WARN: Type inference failed for: r0v16 */
    /* JADX WARN: Type inference failed for: r0v17 */
    /* JADX WARN: Type inference failed for: r0v5, types: [boolean] */
    /* JADX WARN: Type inference failed for: r0v6 */
    /* JADX WARN: Type inference failed for: r0v7 */
    /* JADX WARN: Type inference failed for: r0v8 */
    /* JADX WARN: Type inference failed for: r0v9 */
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.p397ta.utdid2.p400b.p401a.InterfaceC4139b m4689a(java.lang.String r6, int r7) {
        /*
            r5 = this;
            java.io.File r6 = r5.m4688b(r6)
            java.lang.Object r0 = com.p397ta.utdid2.p400b.p401a.C4141d.f10829b
            monitor-enter(r0)
            java.util.HashMap<java.io.File, com.ta.utdid2.b.a.d$a> r1 = r5.f10832a     // Catch: java.lang.Throwable -> Lb3
            java.lang.Object r1 = r1.get(r6)     // Catch: java.lang.Throwable -> Lb3
            com.ta.utdid2.b.a.d$a r1 = (com.p397ta.utdid2.p400b.p401a.C4141d.a) r1     // Catch: java.lang.Throwable -> Lb3
            if (r1 == 0) goto L19
            boolean r2 = r1.m4697d()     // Catch: java.lang.Throwable -> Lb3
            if (r2 != 0) goto L19
            monitor-exit(r0)     // Catch: java.lang.Throwable -> Lb3
            return r1
        L19:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> Lb3
            java.io.File r0 = m4684a(r6)
            boolean r2 = r0.exists()
            if (r2 == 0) goto L2a
            r6.delete()
            r0.renameTo(r6)
        L2a:
            boolean r0 = r6.exists()
            r2 = 0
            if (r0 == 0) goto L90
            boolean r0 = r6.canRead()
            if (r0 == 0) goto L90
            java.io.FileInputStream r0 = new java.io.FileInputStream     // Catch: java.lang.Throwable -> L52 java.lang.Exception -> L54 org.xmlpull.v1.XmlPullParserException -> L5c
            r0.<init>(r6)     // Catch: java.lang.Throwable -> L52 java.lang.Exception -> L54 org.xmlpull.v1.XmlPullParserException -> L5c
            java.util.HashMap r2 = com.p397ta.utdid2.p400b.p401a.C4142e.m4700a(r0)     // Catch: java.lang.Throwable -> L47 java.lang.Exception -> L4a org.xmlpull.v1.XmlPullParserException -> L4e
            r0.close()     // Catch: java.lang.Throwable -> L47 java.lang.Exception -> L4a org.xmlpull.v1.XmlPullParserException -> L4e
            r0.close()     // Catch: java.lang.Throwable -> L90
            goto L90
        L47:
            r6 = move-exception
            r2 = r0
            goto L7d
        L4a:
            r4 = r2
            r2 = r0
            r0 = r4
            goto L55
        L4e:
            r4 = r2
            r2 = r0
            r0 = r4
            goto L5d
        L52:
            r6 = move-exception
            goto L7d
        L54:
            r0 = r2
        L55:
            if (r2 == 0) goto L5a
            r2.close()     // Catch: java.lang.Throwable -> L5a
        L5a:
            r2 = r0
            goto L90
        L5c:
            r0 = r2
        L5d:
            java.io.FileInputStream r3 = new java.io.FileInputStream     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L83
            r3.<init>(r6)     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L83
            int r2 = r3.available()     // Catch: java.lang.Throwable -> L71 java.lang.Exception -> L74
            byte[] r2 = new byte[r2]     // Catch: java.lang.Throwable -> L71 java.lang.Exception -> L74
            r3.read(r2)     // Catch: java.lang.Throwable -> L71 java.lang.Exception -> L74
            r3.close()     // Catch: java.lang.Throwable -> L6f
            goto L8a
        L6f:
            goto L8a
        L71:
            r6 = move-exception
            r2 = r3
            goto L77
        L74:
            r2 = r3
            goto L84
        L76:
            r6 = move-exception
        L77:
            if (r2 == 0) goto L7c
            r2.close()     // Catch: java.lang.Throwable -> L7c
        L7c:
            throw r6     // Catch: java.lang.Throwable -> L52
        L7d:
            if (r2 == 0) goto L82
            r2.close()     // Catch: java.lang.Throwable -> L82
        L82:
            throw r6
        L83:
        L84:
            if (r2 == 0) goto L89
            r2.close()     // Catch: java.lang.Throwable -> L89
        L89:
            r3 = r2
        L8a:
            if (r3 == 0) goto L5a
            r3.close()     // Catch: java.lang.Throwable -> L5a
            goto L5a
        L90:
            java.lang.Object r3 = com.p397ta.utdid2.p400b.p401a.C4141d.f10829b
            monitor-enter(r3)
            if (r1 == 0) goto L99
            r1.m4695a(r2)     // Catch: java.lang.Throwable -> Lb0
            goto Lae
        L99:
            java.util.HashMap<java.io.File, com.ta.utdid2.b.a.d$a> r0 = r5.f10832a     // Catch: java.lang.Throwable -> Lb0
            java.lang.Object r0 = r0.get(r6)     // Catch: java.lang.Throwable -> Lb0
            r1 = r0
            com.ta.utdid2.b.a.d$a r1 = (com.p397ta.utdid2.p400b.p401a.C4141d.a) r1     // Catch: java.lang.Throwable -> Lb0
            if (r1 != 0) goto Lae
            com.ta.utdid2.b.a.d$a r1 = new com.ta.utdid2.b.a.d$a     // Catch: java.lang.Throwable -> Lb0
            r1.<init>(r6, r7, r2)     // Catch: java.lang.Throwable -> Lb0
            java.util.HashMap<java.io.File, com.ta.utdid2.b.a.d$a> r7 = r5.f10832a     // Catch: java.lang.Throwable -> Lb0
            r7.put(r6, r1)     // Catch: java.lang.Throwable -> Lb0
        Lae:
            monitor-exit(r3)     // Catch: java.lang.Throwable -> Lb0
            return r1
        Lb0:
            r6 = move-exception
            monitor-exit(r3)     // Catch: java.lang.Throwable -> Lb0
            throw r6
        Lb3:
            r6 = move-exception
            monitor-exit(r0)     // Catch: java.lang.Throwable -> Lb3
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.p397ta.utdid2.p400b.p401a.C4141d.m4689a(java.lang.String, int):com.ta.utdid2.b.a.b");
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: a */
    public static File m4684a(File file) {
        return new File(file.getPath() + ".bak");
    }
}
