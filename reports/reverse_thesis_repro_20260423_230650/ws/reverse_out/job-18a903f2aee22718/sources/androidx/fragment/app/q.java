package androidx.fragment.app;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

/* JADX INFO: loaded from: classes.dex */
class q implements LayoutInflater.Factory2 {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    final x f5014b;

    class a implements View.OnAttachStateChangeListener {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ D f5015b;

        a(D d3) {
            this.f5015b = d3;
        }

        @Override // android.view.View.OnAttachStateChangeListener
        public void onViewAttachedToWindow(View view) {
            Fragment fragmentK = this.f5015b.k();
            this.f5015b.m();
            L.n((ViewGroup) fragmentK.f4764J.getParent(), q.this.f5014b).j();
        }

        @Override // android.view.View.OnAttachStateChangeListener
        public void onViewDetachedFromWindow(View view) {
        }
    }

    q(x xVar) {
        this.f5014b = xVar;
    }

    @Override // android.view.LayoutInflater.Factory
    public View onCreateView(String str, Context context, AttributeSet attributeSet) {
        return onCreateView(null, str, context, attributeSet);
    }

    @Override // android.view.LayoutInflater.Factory2
    public View onCreateView(View view, String str, Context context, AttributeSet attributeSet) {
        D dV;
        if (C0301m.class.getName().equals(str)) {
            return new C0301m(context, attributeSet, this.f5014b);
        }
        if (!"fragment".equals(str)) {
            return null;
        }
        String attributeValue = attributeSet.getAttributeValue(null, "class");
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, A.c.f9a);
        if (attributeValue == null) {
            attributeValue = typedArrayObtainStyledAttributes.getString(A.c.f10b);
        }
        int resourceId = typedArrayObtainStyledAttributes.getResourceId(A.c.f11c, -1);
        String string = typedArrayObtainStyledAttributes.getString(A.c.f12d);
        typedArrayObtainStyledAttributes.recycle();
        if (attributeValue == null || !o.b(context.getClassLoader(), attributeValue)) {
            return null;
        }
        int id = view != null ? view.getId() : 0;
        if (id == -1 && resourceId == -1 && string == null) {
            throw new IllegalArgumentException(attributeSet.getPositionDescription() + ": Must specify unique android:id, android:tag, or have a parent with an id for " + attributeValue);
        }
        Fragment fragmentG0 = resourceId != -1 ? this.f5014b.g0(resourceId) : null;
        if (fragmentG0 == null && string != null) {
            fragmentG0 = this.f5014b.h0(string);
        }
        if (fragmentG0 == null && id != -1) {
            fragmentG0 = this.f5014b.g0(id);
        }
        if (fragmentG0 == null) {
            fragmentG0 = this.f5014b.r0().a(context.getClassLoader(), attributeValue);
            fragmentG0.f4797p = true;
            fragmentG0.f4806y = resourceId != 0 ? resourceId : id;
            fragmentG0.f4807z = id;
            fragmentG0.f4755A = string;
            fragmentG0.f4798q = true;
            x xVar = this.f5014b;
            fragmentG0.f4802u = xVar;
            fragmentG0.f4803v = xVar.t0();
            fragmentG0.v0(this.f5014b.t0().k(), attributeSet, fragmentG0.f4784c);
            dV = this.f5014b.j(fragmentG0);
            if (x.G0(2)) {
                Log.v("FragmentManager", "Fragment " + fragmentG0 + " has been inflated via the <fragment> tag: id=0x" + Integer.toHexString(resourceId));
            }
        } else {
            if (fragmentG0.f4798q) {
                throw new IllegalArgumentException(attributeSet.getPositionDescription() + ": Duplicate id 0x" + Integer.toHexString(resourceId) + ", tag " + string + ", or parent id 0x" + Integer.toHexString(id) + " with another fragment for " + attributeValue);
            }
            fragmentG0.f4798q = true;
            x xVar2 = this.f5014b;
            fragmentG0.f4802u = xVar2;
            fragmentG0.f4803v = xVar2.t0();
            fragmentG0.v0(this.f5014b.t0().k(), attributeSet, fragmentG0.f4784c);
            dV = this.f5014b.v(fragmentG0);
            if (x.G0(2)) {
                Log.v("FragmentManager", "Retained Fragment " + fragmentG0 + " has been re-attached via the <fragment> tag: id=0x" + Integer.toHexString(resourceId));
            }
        }
        ViewGroup viewGroup = (ViewGroup) view;
        B.c.g(fragmentG0, viewGroup);
        fragmentG0.f4763I = viewGroup;
        dV.m();
        dV.j();
        View view2 = fragmentG0.f4764J;
        if (view2 == null) {
            throw new IllegalStateException("Fragment " + attributeValue + " did not create a view.");
        }
        if (resourceId != 0) {
            view2.setId(resourceId);
        }
        if (fragmentG0.f4764J.getTag() == null) {
            fragmentG0.f4764J.setTag(string);
        }
        fragmentG0.f4764J.addOnAttachStateChangeListener(new a(dV));
        return fragmentG0.f4764J;
    }
}
