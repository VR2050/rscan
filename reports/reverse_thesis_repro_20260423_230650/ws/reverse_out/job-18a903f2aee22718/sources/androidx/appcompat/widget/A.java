package androidx.appcompat.widget;

import android.R;
import android.content.Context;
import android.content.DialogInterface;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.database.DataSetObserver;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.widget.AdapterView;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.PopupWindow;
import android.widget.Spinner;
import android.widget.SpinnerAdapter;
import android.widget.ThemedSpinnerAdapter;
import androidx.appcompat.app.b;
import d.AbstractC0502a;
import e.AbstractC0510a;

/* JADX INFO: loaded from: classes.dex */
public class A extends Spinner {

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private static final int[] f3591j = {R.attr.spinnerMode};

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0231e f3592b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Context f3593c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private S f3594d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private SpinnerAdapter f3595e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final boolean f3596f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private h f3597g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    int f3598h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    final Rect f3599i;

    class a extends S {

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        final /* synthetic */ f f3600k;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        a(View view, f fVar) {
            super(view);
            this.f3600k = fVar;
        }

        @Override // androidx.appcompat.widget.S
        public i.e b() {
            return this.f3600k;
        }

        @Override // androidx.appcompat.widget.S
        public boolean c() {
            if (A.this.getInternalPopup().a()) {
                return true;
            }
            A.this.b();
            return true;
        }
    }

    class b implements ViewTreeObserver.OnGlobalLayoutListener {
        b() {
        }

        @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
        public void onGlobalLayout() {
            if (!A.this.getInternalPopup().a()) {
                A.this.b();
            }
            ViewTreeObserver viewTreeObserver = A.this.getViewTreeObserver();
            if (viewTreeObserver != null) {
                viewTreeObserver.removeOnGlobalLayoutListener(this);
            }
        }
    }

    private static final class c {
        static void a(ThemedSpinnerAdapter themedSpinnerAdapter, Resources.Theme theme) {
            if (q.c.a(themedSpinnerAdapter.getDropDownViewTheme(), theme)) {
                return;
            }
            themedSpinnerAdapter.setDropDownViewTheme(theme);
        }
    }

    class d implements h, DialogInterface.OnClickListener {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        androidx.appcompat.app.b f3603b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private ListAdapter f3604c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private CharSequence f3605d;

        d() {
        }

        @Override // androidx.appcompat.widget.A.h
        public boolean a() {
            androidx.appcompat.app.b bVar = this.f3603b;
            if (bVar != null) {
                return bVar.isShowing();
            }
            return false;
        }

        @Override // androidx.appcompat.widget.A.h
        public int c() {
            return 0;
        }

        @Override // androidx.appcompat.widget.A.h
        public void dismiss() {
            androidx.appcompat.app.b bVar = this.f3603b;
            if (bVar != null) {
                bVar.dismiss();
                this.f3603b = null;
            }
        }

        @Override // androidx.appcompat.widget.A.h
        public Drawable f() {
            return null;
        }

        @Override // androidx.appcompat.widget.A.h
        public void h(CharSequence charSequence) {
            this.f3605d = charSequence;
        }

        @Override // androidx.appcompat.widget.A.h
        public void i(Drawable drawable) {
            Log.e("AppCompatSpinner", "Cannot set popup background for MODE_DIALOG, ignoring");
        }

        @Override // androidx.appcompat.widget.A.h
        public void j(int i3) {
            Log.e("AppCompatSpinner", "Cannot set vertical offset for MODE_DIALOG, ignoring");
        }

        @Override // androidx.appcompat.widget.A.h
        public void k(int i3) {
            Log.e("AppCompatSpinner", "Cannot set horizontal (original) offset for MODE_DIALOG, ignoring");
        }

        @Override // androidx.appcompat.widget.A.h
        public void l(int i3) {
            Log.e("AppCompatSpinner", "Cannot set horizontal offset for MODE_DIALOG, ignoring");
        }

        @Override // androidx.appcompat.widget.A.h
        public void m(int i3, int i4) {
            if (this.f3604c == null) {
                return;
            }
            b.a aVar = new b.a(A.this.getPopupContext());
            CharSequence charSequence = this.f3605d;
            if (charSequence != null) {
                aVar.m(charSequence);
            }
            androidx.appcompat.app.b bVarA = aVar.l(this.f3604c, A.this.getSelectedItemPosition(), this).a();
            this.f3603b = bVarA;
            ListView listViewM = bVarA.m();
            listViewM.setTextDirection(i3);
            listViewM.setTextAlignment(i4);
            this.f3603b.show();
        }

        @Override // androidx.appcompat.widget.A.h
        public int n() {
            return 0;
        }

        @Override // androidx.appcompat.widget.A.h
        public CharSequence o() {
            return this.f3605d;
        }

        @Override // android.content.DialogInterface.OnClickListener
        public void onClick(DialogInterface dialogInterface, int i3) {
            A.this.setSelection(i3);
            if (A.this.getOnItemClickListener() != null) {
                A.this.performItemClick(null, i3, this.f3604c.getItemId(i3));
            }
            dismiss();
        }

        @Override // androidx.appcompat.widget.A.h
        public void p(ListAdapter listAdapter) {
            this.f3604c = listAdapter;
        }
    }

    private static class e implements ListAdapter, SpinnerAdapter {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private SpinnerAdapter f3607a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private ListAdapter f3608b;

        public e(SpinnerAdapter spinnerAdapter, Resources.Theme theme) {
            this.f3607a = spinnerAdapter;
            if (spinnerAdapter instanceof ListAdapter) {
                this.f3608b = (ListAdapter) spinnerAdapter;
            }
            if (theme == null || !(spinnerAdapter instanceof ThemedSpinnerAdapter)) {
                return;
            }
            c.a((ThemedSpinnerAdapter) spinnerAdapter, theme);
        }

        @Override // android.widget.ListAdapter
        public boolean areAllItemsEnabled() {
            ListAdapter listAdapter = this.f3608b;
            if (listAdapter != null) {
                return listAdapter.areAllItemsEnabled();
            }
            return true;
        }

        @Override // android.widget.Adapter
        public int getCount() {
            SpinnerAdapter spinnerAdapter = this.f3607a;
            if (spinnerAdapter == null) {
                return 0;
            }
            return spinnerAdapter.getCount();
        }

        @Override // android.widget.SpinnerAdapter
        public View getDropDownView(int i3, View view, ViewGroup viewGroup) {
            SpinnerAdapter spinnerAdapter = this.f3607a;
            if (spinnerAdapter == null) {
                return null;
            }
            return spinnerAdapter.getDropDownView(i3, view, viewGroup);
        }

        @Override // android.widget.Adapter
        public Object getItem(int i3) {
            SpinnerAdapter spinnerAdapter = this.f3607a;
            if (spinnerAdapter == null) {
                return null;
            }
            return spinnerAdapter.getItem(i3);
        }

        @Override // android.widget.Adapter
        public long getItemId(int i3) {
            SpinnerAdapter spinnerAdapter = this.f3607a;
            if (spinnerAdapter == null) {
                return -1L;
            }
            return spinnerAdapter.getItemId(i3);
        }

        @Override // android.widget.Adapter
        public int getItemViewType(int i3) {
            return 0;
        }

        @Override // android.widget.Adapter
        public View getView(int i3, View view, ViewGroup viewGroup) {
            return getDropDownView(i3, view, viewGroup);
        }

        @Override // android.widget.Adapter
        public int getViewTypeCount() {
            return 1;
        }

        @Override // android.widget.Adapter
        public boolean hasStableIds() {
            SpinnerAdapter spinnerAdapter = this.f3607a;
            return spinnerAdapter != null && spinnerAdapter.hasStableIds();
        }

        @Override // android.widget.Adapter
        public boolean isEmpty() {
            return getCount() == 0;
        }

        @Override // android.widget.ListAdapter
        public boolean isEnabled(int i3) {
            ListAdapter listAdapter = this.f3608b;
            if (listAdapter != null) {
                return listAdapter.isEnabled(i3);
            }
            return true;
        }

        @Override // android.widget.Adapter
        public void registerDataSetObserver(DataSetObserver dataSetObserver) {
            SpinnerAdapter spinnerAdapter = this.f3607a;
            if (spinnerAdapter != null) {
                spinnerAdapter.registerDataSetObserver(dataSetObserver);
            }
        }

        @Override // android.widget.Adapter
        public void unregisterDataSetObserver(DataSetObserver dataSetObserver) {
            SpinnerAdapter spinnerAdapter = this.f3607a;
            if (spinnerAdapter != null) {
                spinnerAdapter.unregisterDataSetObserver(dataSetObserver);
            }
        }
    }

    class f extends U implements h {

        /* JADX INFO: renamed from: J, reason: collision with root package name */
        private CharSequence f3609J;

        /* JADX INFO: renamed from: K, reason: collision with root package name */
        ListAdapter f3610K;

        /* JADX INFO: renamed from: L, reason: collision with root package name */
        private final Rect f3611L;

        /* JADX INFO: renamed from: M, reason: collision with root package name */
        private int f3612M;

        class a implements AdapterView.OnItemClickListener {

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            final /* synthetic */ A f3614b;

            a(A a3) {
                this.f3614b = a3;
            }

            @Override // android.widget.AdapterView.OnItemClickListener
            public void onItemClick(AdapterView adapterView, View view, int i3, long j3) {
                A.this.setSelection(i3);
                if (A.this.getOnItemClickListener() != null) {
                    f fVar = f.this;
                    A.this.performItemClick(view, i3, fVar.f3610K.getItemId(i3));
                }
                f.this.dismiss();
            }
        }

        class b implements ViewTreeObserver.OnGlobalLayoutListener {
            b() {
            }

            @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
            public void onGlobalLayout() {
                f fVar = f.this;
                if (!fVar.Q(A.this)) {
                    f.this.dismiss();
                } else {
                    f.this.O();
                    f.super.b();
                }
            }
        }

        class c implements PopupWindow.OnDismissListener {

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            final /* synthetic */ ViewTreeObserver.OnGlobalLayoutListener f3617b;

            c(ViewTreeObserver.OnGlobalLayoutListener onGlobalLayoutListener) {
                this.f3617b = onGlobalLayoutListener;
            }

            @Override // android.widget.PopupWindow.OnDismissListener
            public void onDismiss() {
                ViewTreeObserver viewTreeObserver = A.this.getViewTreeObserver();
                if (viewTreeObserver != null) {
                    viewTreeObserver.removeGlobalOnLayoutListener(this.f3617b);
                }
            }
        }

        public f(Context context, AttributeSet attributeSet, int i3) {
            super(context, attributeSet, i3);
            this.f3611L = new Rect();
            z(A.this);
            F(true);
            K(0);
            H(new a(A.this));
        }

        void O() {
            int i3;
            Drawable drawableF = f();
            if (drawableF != null) {
                drawableF.getPadding(A.this.f3599i);
                i3 = r0.b(A.this) ? A.this.f3599i.right : -A.this.f3599i.left;
            } else {
                Rect rect = A.this.f3599i;
                rect.right = 0;
                rect.left = 0;
                i3 = 0;
            }
            int paddingLeft = A.this.getPaddingLeft();
            int paddingRight = A.this.getPaddingRight();
            int width = A.this.getWidth();
            A a3 = A.this;
            int i4 = a3.f3598h;
            if (i4 == -2) {
                int iA = a3.a((SpinnerAdapter) this.f3610K, f());
                int i5 = A.this.getContext().getResources().getDisplayMetrics().widthPixels;
                Rect rect2 = A.this.f3599i;
                int i6 = (i5 - rect2.left) - rect2.right;
                if (iA > i6) {
                    iA = i6;
                }
                B(Math.max(iA, (width - paddingLeft) - paddingRight));
            } else if (i4 == -1) {
                B((width - paddingLeft) - paddingRight);
            } else {
                B(i4);
            }
            l(r0.b(A.this) ? i3 + (((width - paddingRight) - v()) - P()) : i3 + paddingLeft + P());
        }

        public int P() {
            return this.f3612M;
        }

        boolean Q(View view) {
            return view.isAttachedToWindow() && view.getGlobalVisibleRect(this.f3611L);
        }

        @Override // androidx.appcompat.widget.A.h
        public void h(CharSequence charSequence) {
            this.f3609J = charSequence;
        }

        @Override // androidx.appcompat.widget.A.h
        public void k(int i3) {
            this.f3612M = i3;
        }

        @Override // androidx.appcompat.widget.A.h
        public void m(int i3, int i4) {
            ViewTreeObserver viewTreeObserver;
            boolean zA = a();
            O();
            E(2);
            super.b();
            ListView listViewG = g();
            listViewG.setChoiceMode(1);
            listViewG.setTextDirection(i3);
            listViewG.setTextAlignment(i4);
            L(A.this.getSelectedItemPosition());
            if (zA || (viewTreeObserver = A.this.getViewTreeObserver()) == null) {
                return;
            }
            b bVar = new b();
            viewTreeObserver.addOnGlobalLayoutListener(bVar);
            G(new c(bVar));
        }

        @Override // androidx.appcompat.widget.A.h
        public CharSequence o() {
            return this.f3609J;
        }

        @Override // androidx.appcompat.widget.U, androidx.appcompat.widget.A.h
        public void p(ListAdapter listAdapter) {
            super.p(listAdapter);
            this.f3610K = listAdapter;
        }
    }

    static class g extends View.BaseSavedState {
        public static final Parcelable.Creator<g> CREATOR = new a();

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        boolean f3619a;

        class a implements Parcelable.Creator {
            a() {
            }

            @Override // android.os.Parcelable.Creator
            /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
            public g createFromParcel(Parcel parcel) {
                return new g(parcel);
            }

            @Override // android.os.Parcelable.Creator
            /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
            public g[] newArray(int i3) {
                return new g[i3];
            }
        }

        g(Parcelable parcelable) {
            super(parcelable);
        }

        @Override // android.view.View.BaseSavedState, android.view.AbsSavedState, android.os.Parcelable
        public void writeToParcel(Parcel parcel, int i3) {
            super.writeToParcel(parcel, i3);
            parcel.writeByte(this.f3619a ? (byte) 1 : (byte) 0);
        }

        g(Parcel parcel) {
            super(parcel);
            this.f3619a = parcel.readByte() != 0;
        }
    }

    interface h {
        boolean a();

        int c();

        void dismiss();

        Drawable f();

        void h(CharSequence charSequence);

        void i(Drawable drawable);

        void j(int i3);

        void k(int i3);

        void l(int i3);

        void m(int i3, int i4);

        int n();

        CharSequence o();

        void p(ListAdapter listAdapter);
    }

    public A(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, AbstractC0502a.f8785F);
    }

    int a(SpinnerAdapter spinnerAdapter, Drawable drawable) {
        int i3 = 0;
        if (spinnerAdapter == null) {
            return 0;
        }
        int iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(getMeasuredWidth(), 0);
        int iMakeMeasureSpec2 = View.MeasureSpec.makeMeasureSpec(getMeasuredHeight(), 0);
        int iMax = Math.max(0, getSelectedItemPosition());
        int iMin = Math.min(spinnerAdapter.getCount(), iMax + 15);
        View view = null;
        int iMax2 = 0;
        for (int iMax3 = Math.max(0, iMax - (15 - (iMin - iMax))); iMax3 < iMin; iMax3++) {
            int itemViewType = spinnerAdapter.getItemViewType(iMax3);
            if (itemViewType != i3) {
                view = null;
                i3 = itemViewType;
            }
            view = spinnerAdapter.getView(iMax3, view, this);
            if (view.getLayoutParams() == null) {
                view.setLayoutParams(new ViewGroup.LayoutParams(-2, -2));
            }
            view.measure(iMakeMeasureSpec, iMakeMeasureSpec2);
            iMax2 = Math.max(iMax2, view.getMeasuredWidth());
        }
        if (drawable == null) {
            return iMax2;
        }
        drawable.getPadding(this.f3599i);
        Rect rect = this.f3599i;
        return iMax2 + rect.left + rect.right;
    }

    void b() {
        this.f3597g.m(getTextDirection(), getTextAlignment());
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void drawableStateChanged() {
        super.drawableStateChanged();
        C0231e c0231e = this.f3592b;
        if (c0231e != null) {
            c0231e.b();
        }
    }

    @Override // android.widget.Spinner
    public int getDropDownHorizontalOffset() {
        h hVar = this.f3597g;
        return hVar != null ? hVar.c() : super.getDropDownHorizontalOffset();
    }

    @Override // android.widget.Spinner
    public int getDropDownVerticalOffset() {
        h hVar = this.f3597g;
        return hVar != null ? hVar.n() : super.getDropDownVerticalOffset();
    }

    @Override // android.widget.Spinner
    public int getDropDownWidth() {
        return this.f3597g != null ? this.f3598h : super.getDropDownWidth();
    }

    final h getInternalPopup() {
        return this.f3597g;
    }

    @Override // android.widget.Spinner
    public Drawable getPopupBackground() {
        h hVar = this.f3597g;
        return hVar != null ? hVar.f() : super.getPopupBackground();
    }

    @Override // android.widget.Spinner
    public Context getPopupContext() {
        return this.f3593c;
    }

    @Override // android.widget.Spinner
    public CharSequence getPrompt() {
        h hVar = this.f3597g;
        return hVar != null ? hVar.o() : super.getPrompt();
    }

    public ColorStateList getSupportBackgroundTintList() {
        C0231e c0231e = this.f3592b;
        if (c0231e != null) {
            return c0231e.c();
        }
        return null;
    }

    public PorterDuff.Mode getSupportBackgroundTintMode() {
        C0231e c0231e = this.f3592b;
        if (c0231e != null) {
            return c0231e.d();
        }
        return null;
    }

    @Override // android.widget.Spinner, android.widget.AdapterView, android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        h hVar = this.f3597g;
        if (hVar == null || !hVar.a()) {
            return;
        }
        this.f3597g.dismiss();
    }

    @Override // android.widget.Spinner, android.widget.AbsSpinner, android.view.View
    protected void onMeasure(int i3, int i4) {
        super.onMeasure(i3, i4);
        if (this.f3597g == null || View.MeasureSpec.getMode(i3) != Integer.MIN_VALUE) {
            return;
        }
        setMeasuredDimension(Math.min(Math.max(getMeasuredWidth(), a(getAdapter(), getBackground())), View.MeasureSpec.getSize(i3)), getMeasuredHeight());
    }

    @Override // android.widget.Spinner, android.widget.AbsSpinner, android.view.View
    public void onRestoreInstanceState(Parcelable parcelable) {
        ViewTreeObserver viewTreeObserver;
        g gVar = (g) parcelable;
        super.onRestoreInstanceState(gVar.getSuperState());
        if (!gVar.f3619a || (viewTreeObserver = getViewTreeObserver()) == null) {
            return;
        }
        viewTreeObserver.addOnGlobalLayoutListener(new b());
    }

    @Override // android.widget.Spinner, android.widget.AbsSpinner, android.view.View
    public Parcelable onSaveInstanceState() {
        g gVar = new g(super.onSaveInstanceState());
        h hVar = this.f3597g;
        gVar.f3619a = hVar != null && hVar.a();
        return gVar;
    }

    @Override // android.widget.Spinner, android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        S s3 = this.f3594d;
        if (s3 == null || !s3.onTouch(this, motionEvent)) {
            return super.onTouchEvent(motionEvent);
        }
        return true;
    }

    @Override // android.widget.Spinner, android.view.View
    public boolean performClick() {
        h hVar = this.f3597g;
        if (hVar == null) {
            return super.performClick();
        }
        if (hVar.a()) {
            return true;
        }
        b();
        return true;
    }

    @Override // android.view.View
    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        C0231e c0231e = this.f3592b;
        if (c0231e != null) {
            c0231e.f(drawable);
        }
    }

    @Override // android.view.View
    public void setBackgroundResource(int i3) {
        super.setBackgroundResource(i3);
        C0231e c0231e = this.f3592b;
        if (c0231e != null) {
            c0231e.g(i3);
        }
    }

    @Override // android.widget.Spinner
    public void setDropDownHorizontalOffset(int i3) {
        h hVar = this.f3597g;
        if (hVar == null) {
            super.setDropDownHorizontalOffset(i3);
        } else {
            hVar.k(i3);
            this.f3597g.l(i3);
        }
    }

    @Override // android.widget.Spinner
    public void setDropDownVerticalOffset(int i3) {
        h hVar = this.f3597g;
        if (hVar != null) {
            hVar.j(i3);
        } else {
            super.setDropDownVerticalOffset(i3);
        }
    }

    @Override // android.widget.Spinner
    public void setDropDownWidth(int i3) {
        if (this.f3597g != null) {
            this.f3598h = i3;
        } else {
            super.setDropDownWidth(i3);
        }
    }

    @Override // android.widget.Spinner
    public void setPopupBackgroundDrawable(Drawable drawable) {
        h hVar = this.f3597g;
        if (hVar != null) {
            hVar.i(drawable);
        } else {
            super.setPopupBackgroundDrawable(drawable);
        }
    }

    @Override // android.widget.Spinner
    public void setPopupBackgroundResource(int i3) {
        setPopupBackgroundDrawable(AbstractC0510a.b(getPopupContext(), i3));
    }

    @Override // android.widget.Spinner
    public void setPrompt(CharSequence charSequence) {
        h hVar = this.f3597g;
        if (hVar != null) {
            hVar.h(charSequence);
        } else {
            super.setPrompt(charSequence);
        }
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        C0231e c0231e = this.f3592b;
        if (c0231e != null) {
            c0231e.i(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(PorterDuff.Mode mode) {
        C0231e c0231e = this.f3592b;
        if (c0231e != null) {
            c0231e.j(mode);
        }
    }

    public A(Context context, AttributeSet attributeSet, int i3) {
        this(context, attributeSet, i3, -1);
    }

    @Override // android.widget.AdapterView
    public void setAdapter(SpinnerAdapter spinnerAdapter) {
        if (!this.f3596f) {
            this.f3595e = spinnerAdapter;
            return;
        }
        super.setAdapter(spinnerAdapter);
        if (this.f3597g != null) {
            Context context = this.f3593c;
            if (context == null) {
                context = getContext();
            }
            this.f3597g.p(new e(spinnerAdapter, context.getTheme()));
        }
    }

    public A(Context context, AttributeSet attributeSet, int i3, int i4) {
        this(context, attributeSet, i3, i4, null);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0070  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00aa  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00c2  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00db  */
    /* JADX WARN: Type inference failed for: r11v10 */
    /* JADX WARN: Type inference failed for: r11v11 */
    /* JADX WARN: Type inference failed for: r11v12 */
    /* JADX WARN: Type inference failed for: r11v3 */
    /* JADX WARN: Type inference failed for: r11v4 */
    /* JADX WARN: Type inference failed for: r11v7, types: [android.content.res.TypedArray] */
    /* JADX WARN: Type inference failed for: r2v2 */
    /* JADX WARN: Type inference failed for: r2v3 */
    /* JADX WARN: Type inference failed for: r2v4, types: [android.content.res.TypedArray] */
    /* JADX WARN: Type inference failed for: r6v0, types: [android.view.View, androidx.appcompat.widget.A] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public A(android.content.Context r7, android.util.AttributeSet r8, int r9, int r10, android.content.res.Resources.Theme r11) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 230
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.A.<init>(android.content.Context, android.util.AttributeSet, int, int, android.content.res.Resources$Theme):void");
    }
}
