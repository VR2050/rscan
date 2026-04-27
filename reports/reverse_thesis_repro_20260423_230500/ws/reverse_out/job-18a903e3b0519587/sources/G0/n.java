package G0;

import a0.InterfaceC0217c;
import b0.AbstractC0311a;

/* JADX INFO: loaded from: classes.dex */
public interface n extends x, InterfaceC0217c {

    public static class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public final Object f807a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public final AbstractC0311a f808b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public int f809c = 0;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        public boolean f810d = false;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        public int f811e = 0;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        public int f812f;

        private a(Object obj, AbstractC0311a abstractC0311a, b bVar, int i3) {
            this.f807a = X.k.g(obj);
            this.f808b = (AbstractC0311a) X.k.g(AbstractC0311a.A(abstractC0311a));
            this.f812f = i3;
        }

        public static a a(Object obj, AbstractC0311a abstractC0311a, int i3, b bVar) {
            return new a(obj, abstractC0311a, bVar, i3);
        }

        public static a b(Object obj, AbstractC0311a abstractC0311a, b bVar) {
            return a(obj, abstractC0311a, -1, bVar);
        }
    }

    public interface b {
    }
}
