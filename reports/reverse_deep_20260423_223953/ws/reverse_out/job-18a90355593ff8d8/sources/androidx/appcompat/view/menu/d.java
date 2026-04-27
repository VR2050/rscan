package androidx.appcompat.view.menu;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import androidx.appcompat.view.menu.k;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes.dex */
public class d extends BaseAdapter {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    e f3483a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f3484b = -1;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f3485c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final boolean f3486d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final LayoutInflater f3487e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final int f3488f;

    public d(e eVar, LayoutInflater layoutInflater, boolean z3, int i3) {
        this.f3486d = z3;
        this.f3487e = layoutInflater;
        this.f3483a = eVar;
        this.f3488f = i3;
        a();
    }

    void a() {
        g gVarV = this.f3483a.v();
        if (gVarV != null) {
            ArrayList arrayListZ = this.f3483a.z();
            int size = arrayListZ.size();
            for (int i3 = 0; i3 < size; i3++) {
                if (((g) arrayListZ.get(i3)) == gVarV) {
                    this.f3484b = i3;
                    return;
                }
            }
        }
        this.f3484b = -1;
    }

    public e b() {
        return this.f3483a;
    }

    @Override // android.widget.Adapter
    /* JADX INFO: renamed from: c, reason: merged with bridge method [inline-methods] */
    public g getItem(int i3) {
        ArrayList arrayListZ = this.f3486d ? this.f3483a.z() : this.f3483a.E();
        int i4 = this.f3484b;
        if (i4 >= 0 && i3 >= i4) {
            i3++;
        }
        return (g) arrayListZ.get(i3);
    }

    public void d(boolean z3) {
        this.f3485c = z3;
    }

    @Override // android.widget.Adapter
    public int getCount() {
        return this.f3484b < 0 ? (this.f3486d ? this.f3483a.z() : this.f3483a.E()).size() : r0.size() - 1;
    }

    @Override // android.widget.Adapter
    public long getItemId(int i3) {
        return i3;
    }

    @Override // android.widget.Adapter
    public View getView(int i3, View view, ViewGroup viewGroup) {
        if (view == null) {
            view = this.f3487e.inflate(this.f3488f, viewGroup, false);
        }
        int groupId = getItem(i3).getGroupId();
        int i4 = i3 - 1;
        ListMenuItemView listMenuItemView = (ListMenuItemView) view;
        listMenuItemView.setGroupDividerEnabled(this.f3483a.G() && groupId != (i4 >= 0 ? getItem(i4).getGroupId() : groupId));
        k.a aVar = (k.a) view;
        if (this.f3485c) {
            listMenuItemView.setForceShowIcon(true);
        }
        aVar.e(getItem(i3), 0);
        return view;
    }

    @Override // android.widget.BaseAdapter
    public void notifyDataSetChanged() {
        a();
        super.notifyDataSetChanged();
    }
}
