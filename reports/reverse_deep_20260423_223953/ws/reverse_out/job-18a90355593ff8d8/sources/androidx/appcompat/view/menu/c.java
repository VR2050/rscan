package androidx.appcompat.view.menu;

import android.content.Context;
import android.view.ContextThemeWrapper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.BaseAdapter;
import android.widget.ListAdapter;
import androidx.appcompat.view.menu.j;
import androidx.appcompat.view.menu.k;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes.dex */
public class c implements j, AdapterView.OnItemClickListener {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    Context f3472b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    LayoutInflater f3473c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    e f3474d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    ExpandedMenuView f3475e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    int f3476f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    int f3477g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    int f3478h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private j.a f3479i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    a f3480j;

    private class a extends BaseAdapter {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private int f3481a = -1;

        public a() {
            a();
        }

        void a() {
            g gVarV = c.this.f3474d.v();
            if (gVarV != null) {
                ArrayList arrayListZ = c.this.f3474d.z();
                int size = arrayListZ.size();
                for (int i3 = 0; i3 < size; i3++) {
                    if (((g) arrayListZ.get(i3)) == gVarV) {
                        this.f3481a = i3;
                        return;
                    }
                }
            }
            this.f3481a = -1;
        }

        @Override // android.widget.Adapter
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public g getItem(int i3) {
            ArrayList arrayListZ = c.this.f3474d.z();
            int i4 = i3 + c.this.f3476f;
            int i5 = this.f3481a;
            if (i5 >= 0 && i4 >= i5) {
                i4++;
            }
            return (g) arrayListZ.get(i4);
        }

        @Override // android.widget.Adapter
        public int getCount() {
            int size = c.this.f3474d.z().size() - c.this.f3476f;
            return this.f3481a < 0 ? size : size - 1;
        }

        @Override // android.widget.Adapter
        public long getItemId(int i3) {
            return i3;
        }

        @Override // android.widget.Adapter
        public View getView(int i3, View view, ViewGroup viewGroup) {
            if (view == null) {
                c cVar = c.this;
                view = cVar.f3473c.inflate(cVar.f3478h, viewGroup, false);
            }
            ((k.a) view).e(getItem(i3), 0);
            return view;
        }

        @Override // android.widget.BaseAdapter
        public void notifyDataSetChanged() {
            a();
            super.notifyDataSetChanged();
        }
    }

    public c(Context context, int i3) {
        this(i3, 0);
        this.f3472b = context;
        this.f3473c = LayoutInflater.from(context);
    }

    public ListAdapter a() {
        if (this.f3480j == null) {
            this.f3480j = new a();
        }
        return this.f3480j;
    }

    public k b(ViewGroup viewGroup) {
        if (this.f3475e == null) {
            this.f3475e = (ExpandedMenuView) this.f3473c.inflate(d.g.f8916g, viewGroup, false);
            if (this.f3480j == null) {
                this.f3480j = new a();
            }
            this.f3475e.setAdapter((ListAdapter) this.f3480j);
            this.f3475e.setOnItemClickListener(this);
        }
        return this.f3475e;
    }

    @Override // androidx.appcompat.view.menu.j
    public void c(e eVar, boolean z3) {
        j.a aVar = this.f3479i;
        if (aVar != null) {
            aVar.c(eVar, z3);
        }
    }

    @Override // androidx.appcompat.view.menu.j
    public void d(Context context, e eVar) {
        if (this.f3477g != 0) {
            ContextThemeWrapper contextThemeWrapper = new ContextThemeWrapper(context, this.f3477g);
            this.f3472b = contextThemeWrapper;
            this.f3473c = LayoutInflater.from(contextThemeWrapper);
        } else if (this.f3472b != null) {
            this.f3472b = context;
            if (this.f3473c == null) {
                this.f3473c = LayoutInflater.from(context);
            }
        }
        this.f3474d = eVar;
        a aVar = this.f3480j;
        if (aVar != null) {
            aVar.notifyDataSetChanged();
        }
    }

    @Override // androidx.appcompat.view.menu.j
    public boolean e(m mVar) {
        if (!mVar.hasVisibleItems()) {
            return false;
        }
        new f(mVar).b(null);
        j.a aVar = this.f3479i;
        if (aVar == null) {
            return true;
        }
        aVar.d(mVar);
        return true;
    }

    @Override // androidx.appcompat.view.menu.j
    public void f(boolean z3) {
        a aVar = this.f3480j;
        if (aVar != null) {
            aVar.notifyDataSetChanged();
        }
    }

    @Override // androidx.appcompat.view.menu.j
    public boolean h() {
        return false;
    }

    @Override // androidx.appcompat.view.menu.j
    public boolean i(e eVar, g gVar) {
        return false;
    }

    @Override // androidx.appcompat.view.menu.j
    public boolean j(e eVar, g gVar) {
        return false;
    }

    @Override // androidx.appcompat.view.menu.j
    public void k(j.a aVar) {
        this.f3479i = aVar;
    }

    @Override // android.widget.AdapterView.OnItemClickListener
    public void onItemClick(AdapterView adapterView, View view, int i3, long j3) {
        this.f3474d.N(this.f3480j.getItem(i3), this, 0);
    }

    public c(int i3, int i4) {
        this.f3478h = i3;
        this.f3477g = i4;
    }
}
