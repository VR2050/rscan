package p005b.p199l.p200a.p201a.p248o1.p249h0;

import androidx.annotation.Nullable;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/* renamed from: b.l.a.a.o1.h0.r */
/* loaded from: classes.dex */
public final class C2312r implements InterfaceC2310p {

    /* renamed from: a */
    public static final C2312r f5895a = new C2312r(Collections.emptyMap());

    /* renamed from: b */
    public int f5896b;

    /* renamed from: c */
    public final Map<String, byte[]> f5897c;

    public C2312r() {
        this(Collections.emptyMap());
    }

    /* renamed from: c */
    public static boolean m2250c(Map<String, byte[]> map, Map<String, byte[]> map2) {
        if (map.size() != map2.size()) {
            return false;
        }
        for (Map.Entry<String, byte[]> entry : map.entrySet()) {
            if (!Arrays.equals(entry.getValue(), map2.get(entry.getKey()))) {
                return false;
            }
        }
        return true;
    }

    /* renamed from: a */
    public C2312r m2251a(C2311q c2311q) {
        byte[] bArr;
        HashMap hashMap = new HashMap(this.f5897c);
        Objects.requireNonNull(c2311q);
        List unmodifiableList = Collections.unmodifiableList(new ArrayList(c2311q.f5894b));
        for (int i2 = 0; i2 < unmodifiableList.size(); i2++) {
            hashMap.remove(unmodifiableList.get(i2));
        }
        HashMap hashMap2 = new HashMap(c2311q.f5893a);
        for (Map.Entry entry : hashMap2.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof byte[]) {
                byte[] bArr2 = (byte[]) value;
                entry.setValue(Arrays.copyOf(bArr2, bArr2.length));
            }
        }
        Map unmodifiableMap = Collections.unmodifiableMap(hashMap2);
        for (String str : unmodifiableMap.keySet()) {
            Object obj = unmodifiableMap.get(str);
            if (obj instanceof Long) {
                bArr = ByteBuffer.allocate(8).putLong(((Long) obj).longValue()).array();
            } else if (obj instanceof String) {
                bArr = ((String) obj).getBytes(Charset.forName("UTF-8"));
            } else {
                if (!(obj instanceof byte[])) {
                    throw new IllegalArgumentException();
                }
                bArr = (byte[]) obj;
            }
            hashMap.put(str, bArr);
        }
        return m2250c(this.f5897c, hashMap) ? this : new C2312r(hashMap);
    }

    /* renamed from: b */
    public final long m2252b(String str, long j2) {
        return this.f5897c.containsKey(str) ? ByteBuffer.wrap(this.f5897c.get(str)).getLong() : j2;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2312r.class != obj.getClass()) {
            return false;
        }
        return m2250c(this.f5897c, ((C2312r) obj).f5897c);
    }

    public int hashCode() {
        if (this.f5896b == 0) {
            int i2 = 0;
            for (Map.Entry<String, byte[]> entry : this.f5897c.entrySet()) {
                i2 += Arrays.hashCode(entry.getValue()) ^ entry.getKey().hashCode();
            }
            this.f5896b = i2;
        }
        return this.f5896b;
    }

    public C2312r(Map<String, byte[]> map) {
        this.f5897c = Collections.unmodifiableMap(map);
    }
}
