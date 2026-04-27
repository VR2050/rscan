package R2;

import java.security.MessageDigest;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public abstract class d {

    public static final class a implements c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final MessageDigest f2638a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ String f2639b;

        a(String str) {
            this.f2639b = str;
            this.f2638a = MessageDigest.getInstance(str);
        }

        @Override // R2.c
        public byte[] a() {
            return this.f2638a.digest();
        }

        @Override // R2.c
        public void b(byte[] bArr, int i3, int i4) {
            j.f(bArr, "input");
            this.f2638a.update(bArr, i3, i4);
        }
    }

    public static final c a(String str) {
        j.f(str, "algorithm");
        return new a(str);
    }
}
