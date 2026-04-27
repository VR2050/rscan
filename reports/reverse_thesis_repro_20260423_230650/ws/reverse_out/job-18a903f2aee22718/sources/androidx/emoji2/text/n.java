package androidx.emoji2.text;

import android.graphics.Typeface;
import android.util.SparseArray;
import java.nio.ByteBuffer;
import y.C0720b;

/* JADX INFO: loaded from: classes.dex */
public final class n {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final C0720b f4675a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final char[] f4676b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final a f4677c = new a(1024);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Typeface f4678d;

    static class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final SparseArray f4679a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private p f4680b;

        private a() {
            this(1);
        }

        a a(int i3) {
            SparseArray sparseArray = this.f4679a;
            if (sparseArray == null) {
                return null;
            }
            return (a) sparseArray.get(i3);
        }

        final p b() {
            return this.f4680b;
        }

        void c(p pVar, int i3, int i4) {
            a aVarA = a(pVar.b(i3));
            if (aVarA == null) {
                aVarA = new a();
                this.f4679a.put(pVar.b(i3), aVarA);
            }
            if (i4 > i3) {
                aVarA.c(pVar, i3 + 1, i4);
            } else {
                aVarA.f4680b = pVar;
            }
        }

        a(int i3) {
            this.f4679a = new SparseArray(i3);
        }
    }

    private n(Typeface typeface, C0720b c0720b) {
        this.f4678d = typeface;
        this.f4675a = c0720b;
        this.f4676b = new char[c0720b.k() * 2];
        a(c0720b);
    }

    private void a(C0720b c0720b) {
        int iK = c0720b.k();
        for (int i3 = 0; i3 < iK; i3++) {
            p pVar = new p(this, i3);
            Character.toChars(pVar.f(), this.f4676b, i3 * 2);
            h(pVar);
        }
    }

    public static n b(Typeface typeface, ByteBuffer byteBuffer) {
        try {
            androidx.core.os.f.a("EmojiCompat.MetadataRepo.create");
            return new n(typeface, m.b(byteBuffer));
        } finally {
            androidx.core.os.f.b();
        }
    }

    public char[] c() {
        return this.f4676b;
    }

    public C0720b d() {
        return this.f4675a;
    }

    int e() {
        return this.f4675a.l();
    }

    a f() {
        return this.f4677c;
    }

    Typeface g() {
        return this.f4678d;
    }

    void h(p pVar) {
        q.g.g(pVar, "emoji metadata cannot be null");
        q.g.a(pVar.c() > 0, "invalid metadata codepoint length");
        this.f4677c.c(pVar, 0, pVar.c() - 1);
    }
}
