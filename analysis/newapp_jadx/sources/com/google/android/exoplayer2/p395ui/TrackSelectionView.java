package com.google.android.exoplayer2.p395ui;

import android.R;
import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.util.Pair;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckedTextView;
import android.widget.LinearLayout;
import androidx.annotation.AttrRes;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.source.TrackGroupArray;
import com.google.android.exoplayer2.trackselection.DefaultTrackSelector;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p246n1.C2266d;
import p005b.p199l.p200a.p201a.p246n1.InterfaceC2269g;

/* loaded from: classes.dex */
public class TrackSelectionView extends LinearLayout {

    /* renamed from: c */
    public final int f9706c;

    /* renamed from: e */
    public final LayoutInflater f9707e;

    /* renamed from: f */
    public final CheckedTextView f9708f;

    /* renamed from: g */
    public final CheckedTextView f9709g;

    /* renamed from: h */
    public final ViewOnClickListenerC3323b f9710h;

    /* renamed from: i */
    public final SparseArray<DefaultTrackSelector.SelectionOverride> f9711i;

    /* renamed from: j */
    public boolean f9712j;

    /* renamed from: k */
    public boolean f9713k;

    /* renamed from: l */
    public InterfaceC2269g f9714l;

    /* renamed from: m */
    public TrackGroupArray f9715m;

    /* renamed from: n */
    public boolean f9716n;

    /* renamed from: com.google.android.exoplayer2.ui.TrackSelectionView$b */
    public class ViewOnClickListenerC3323b implements View.OnClickListener {
        public ViewOnClickListenerC3323b(C3322a c3322a) {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            TrackSelectionView trackSelectionView = TrackSelectionView.this;
            if (view == trackSelectionView.f9708f) {
                trackSelectionView.f9716n = true;
                trackSelectionView.f9711i.clear();
            } else {
                if (view != trackSelectionView.f9709g) {
                    trackSelectionView.f9716n = false;
                    Pair pair = (Pair) view.getTag();
                    int intValue = ((Integer) pair.first).intValue();
                    ((Integer) pair.second).intValue();
                    trackSelectionView.f9711i.get(intValue);
                    Objects.requireNonNull(null);
                    throw null;
                }
                trackSelectionView.f9716n = false;
                trackSelectionView.f9711i.clear();
            }
            trackSelectionView.m4125a();
        }
    }

    public TrackSelectionView(Context context) {
        this(context, null);
    }

    /* renamed from: a */
    public final void m4125a() {
        this.f9708f.setChecked(this.f9716n);
        this.f9709g.setChecked(!this.f9716n && this.f9711i.size() == 0);
        throw null;
    }

    /* renamed from: b */
    public final void m4126b() {
        int childCount = getChildCount();
        while (true) {
            childCount--;
            if (childCount < 3) {
                this.f9708f.setEnabled(false);
                this.f9709g.setEnabled(false);
                return;
            }
            removeViewAt(childCount);
        }
    }

    public boolean getIsDisabled() {
        return this.f9716n;
    }

    public List<DefaultTrackSelector.SelectionOverride> getOverrides() {
        ArrayList arrayList = new ArrayList(this.f9711i.size());
        for (int i2 = 0; i2 < this.f9711i.size(); i2++) {
            arrayList.add(this.f9711i.valueAt(i2));
        }
        return arrayList;
    }

    public void setAllowAdaptiveSelections(boolean z) {
        if (this.f9712j != z) {
            this.f9712j = z;
            m4126b();
        }
    }

    public void setAllowMultipleOverrides(boolean z) {
        if (this.f9713k != z) {
            this.f9713k = z;
            if (!z && this.f9711i.size() > 1) {
                for (int size = this.f9711i.size() - 1; size > 0; size--) {
                    this.f9711i.remove(size);
                }
            }
            m4126b();
        }
    }

    public void setShowDisableOption(boolean z) {
        this.f9708f.setVisibility(z ? 0 : 8);
    }

    public void setTrackNameProvider(InterfaceC2269g interfaceC2269g) {
        Objects.requireNonNull(interfaceC2269g);
        this.f9714l = interfaceC2269g;
        m4126b();
    }

    public TrackSelectionView(Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public TrackSelectionView(Context context, @Nullable AttributeSet attributeSet, @AttrRes int i2) {
        super(context, attributeSet, i2);
        setOrientation(1);
        this.f9711i = new SparseArray<>();
        setSaveFromParentEnabled(false);
        TypedArray obtainStyledAttributes = context.getTheme().obtainStyledAttributes(new int[]{R.attr.selectableItemBackground});
        int resourceId = obtainStyledAttributes.getResourceId(0, 0);
        this.f9706c = resourceId;
        obtainStyledAttributes.recycle();
        LayoutInflater from = LayoutInflater.from(context);
        this.f9707e = from;
        ViewOnClickListenerC3323b viewOnClickListenerC3323b = new ViewOnClickListenerC3323b(null);
        this.f9710h = viewOnClickListenerC3323b;
        this.f9714l = new C2266d(getResources());
        this.f9715m = TrackGroupArray.f9396c;
        CheckedTextView checkedTextView = (CheckedTextView) from.inflate(R.layout.simple_list_item_single_choice, (ViewGroup) this, false);
        this.f9708f = checkedTextView;
        checkedTextView.setBackgroundResource(resourceId);
        checkedTextView.setText(R$string.exo_track_selection_none);
        checkedTextView.setEnabled(false);
        checkedTextView.setFocusable(true);
        checkedTextView.setOnClickListener(viewOnClickListenerC3323b);
        checkedTextView.setVisibility(8);
        addView(checkedTextView);
        addView(from.inflate(R$layout.exo_list_divider, (ViewGroup) this, false));
        CheckedTextView checkedTextView2 = (CheckedTextView) from.inflate(R.layout.simple_list_item_single_choice, (ViewGroup) this, false);
        this.f9709g = checkedTextView2;
        checkedTextView2.setBackgroundResource(resourceId);
        checkedTextView2.setText(R$string.exo_track_selection_auto);
        checkedTextView2.setEnabled(false);
        checkedTextView2.setFocusable(true);
        checkedTextView2.setOnClickListener(viewOnClickListenerC3323b);
        addView(checkedTextView2);
    }
}
