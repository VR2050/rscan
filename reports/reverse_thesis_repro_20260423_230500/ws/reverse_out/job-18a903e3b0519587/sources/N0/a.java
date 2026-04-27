package N0;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
public abstract class a implements d {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final Set f1872d = new HashSet(Arrays.asList("encoded_size", "encoded_width", "encoded_height", "uri_source", "image_format", "bitmap_config", "is_rounded", "non_fatal_decode_error", "original_url", "modified_url", "image_color_space"));

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Map f1873b = new HashMap();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private l f1874c;

    @Override // x0.InterfaceC0716a
    public void A(String str, Object obj) {
        if (f1872d.contains(str)) {
            this.f1873b.put(str, obj);
        }
    }

    @Override // N0.k, x0.InterfaceC0716a
    public Map b() {
        return this.f1873b;
    }

    @Override // N0.d
    public o k() {
        return n.f1902d;
    }

    @Override // N0.d
    public boolean m0() {
        return false;
    }

    @Override // x0.InterfaceC0716a
    public void r(Map map) {
        if (map == null) {
            return;
        }
        for (String str : f1872d) {
            Object obj = map.get(str);
            if (obj != null) {
                this.f1873b.put(str, obj);
            }
        }
    }

    @Override // N0.d
    public l s() {
        if (this.f1874c == null) {
            this.f1874c = new m(h(), d(), b0(), k(), b());
        }
        return this.f1874c;
    }
}
