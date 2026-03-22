package com.scwang.smartrefresh.layout.header;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentManager;
import com.scwang.smartrefresh.layout.R$id;
import com.scwang.smartrefresh.layout.R$layout;
import com.scwang.smartrefresh.layout.R$string;
import com.scwang.smartrefresh.layout.R$styleable;
import com.scwang.smartrefresh.layout.internal.InternalClassics;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2897f;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2900i;
import p005b.p340x.p354b.p355a.p357c.C2904c;
import p005b.p340x.p354b.p355a.p357c.EnumC2903b;
import p005b.p340x.p354b.p355a.p359e.C2907a;
import p005b.p340x.p354b.p355a.p359e.C2909c;
import p005b.p340x.p354b.p355a.p361g.InterpolatorC2917b;

/* loaded from: classes2.dex */
public class ClassicsHeader extends InternalClassics<ClassicsHeader> implements InterfaceC2897f {

    /* renamed from: A */
    public String f10717A;

    /* renamed from: B */
    public String f10718B;

    /* renamed from: C */
    public String f10719C;

    /* renamed from: D */
    public String f10720D;

    /* renamed from: E */
    public String f10721E;

    /* renamed from: F */
    public String f10722F;

    /* renamed from: G */
    public String f10723G;

    /* renamed from: t */
    public String f10724t;

    /* renamed from: u */
    public Date f10725u;

    /* renamed from: v */
    public TextView f10726v;

    /* renamed from: w */
    public SharedPreferences f10727w;

    /* renamed from: x */
    public DateFormat f10728x;

    /* renamed from: y */
    public boolean f10729y;

    /* renamed from: z */
    public String f10730z;

    public ClassicsHeader(Context context) {
        this(context, null);
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p360f.InterfaceC2915f
    /* renamed from: e */
    public void mo3379e(@NonNull InterfaceC2900i interfaceC2900i, @NonNull EnumC2903b enumC2903b, @NonNull EnumC2903b enumC2903b2) {
        ImageView imageView = this.f10747h;
        TextView textView = this.f10726v;
        int ordinal = enumC2903b2.ordinal();
        if (ordinal == 0) {
            textView.setVisibility(this.f10729y ? 0 : 8);
        } else if (ordinal != 1) {
            if (ordinal == 5) {
                this.f10746g.setText(this.f10719C);
                imageView.animate().rotation(180.0f);
                return;
            }
            if (ordinal == 7) {
                this.f10746g.setText(this.f10723G);
                imageView.animate().rotation(0.0f);
                return;
            } else if (ordinal == 9 || ordinal == 11) {
                this.f10746g.setText(this.f10717A);
                imageView.setVisibility(8);
                return;
            } else {
                if (ordinal != 12) {
                    return;
                }
                imageView.setVisibility(8);
                textView.setVisibility(this.f10729y ? 4 : 8);
                this.f10746g.setText(this.f10718B);
                return;
            }
        }
        this.f10746g.setText(this.f10730z);
        imageView.setVisibility(0);
        imageView.animate().rotation(0.0f);
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalClassics, com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: j */
    public int mo3354j(@NonNull InterfaceC2900i interfaceC2900i, boolean z) {
        if (z) {
            this.f10746g.setText(this.f10720D);
            if (this.f10725u != null) {
                m4630t(new Date());
            }
        } else {
            this.f10746g.setText(this.f10721E);
        }
        return super.mo3354j(interfaceC2900i, z);
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalClassics
    /* renamed from: r */
    public ClassicsHeader mo4629r(@ColorInt int i2) {
        this.f10726v.setTextColor((16777215 & i2) | (-872415232));
        super.mo4629r(i2);
        return this;
    }

    /* renamed from: t */
    public ClassicsHeader m4630t(Date date) {
        this.f10725u = date;
        this.f10726v.setText(this.f10728x.format(date));
        if (this.f10727w != null && !isInEditMode()) {
            this.f10727w.edit().putLong(this.f10724t, date.getTime()).apply();
        }
        return this;
    }

    public ClassicsHeader(Context context, AttributeSet attributeSet) {
        super(context, attributeSet, 0);
        FragmentManager supportFragmentManager;
        List<Fragment> fragments;
        this.f10724t = "LAST_UPDATE_TIME";
        this.f10729y = true;
        View.inflate(context, R$layout.srl_classics_header, this);
        ImageView imageView = (ImageView) findViewById(R$id.srl_classics_arrow);
        this.f10747h = imageView;
        TextView textView = (TextView) findViewById(R$id.srl_classics_update);
        this.f10726v = textView;
        ImageView imageView2 = (ImageView) findViewById(R$id.srl_classics_progress);
        this.f10748i = imageView2;
        this.f10746g = (TextView) findViewById(R$id.srl_classics_title);
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.ClassicsHeader);
        RelativeLayout.LayoutParams layoutParams = (RelativeLayout.LayoutParams) imageView.getLayoutParams();
        RelativeLayout.LayoutParams layoutParams2 = (RelativeLayout.LayoutParams) imageView2.getLayoutParams();
        new LinearLayout.LayoutParams(-2, -2).topMargin = obtainStyledAttributes.getDimensionPixelSize(R$styleable.ClassicsHeader_srlTextTimeMarginTop, InterpolatorC2917b.m3382c(0.0f));
        int dimensionPixelSize = obtainStyledAttributes.getDimensionPixelSize(R$styleable.ClassicsFooter_srlDrawableMarginRight, InterpolatorC2917b.m3382c(20.0f));
        layoutParams2.rightMargin = dimensionPixelSize;
        layoutParams.rightMargin = dimensionPixelSize;
        int i2 = R$styleable.ClassicsHeader_srlDrawableArrowSize;
        layoutParams.width = obtainStyledAttributes.getLayoutDimension(i2, layoutParams.width);
        layoutParams.height = obtainStyledAttributes.getLayoutDimension(i2, layoutParams.height);
        int i3 = R$styleable.ClassicsHeader_srlDrawableProgressSize;
        layoutParams2.width = obtainStyledAttributes.getLayoutDimension(i3, layoutParams2.width);
        layoutParams2.height = obtainStyledAttributes.getLayoutDimension(i3, layoutParams2.height);
        int i4 = R$styleable.ClassicsHeader_srlDrawableSize;
        layoutParams.width = obtainStyledAttributes.getLayoutDimension(i4, layoutParams.width);
        layoutParams.height = obtainStyledAttributes.getLayoutDimension(i4, layoutParams.height);
        layoutParams2.width = obtainStyledAttributes.getLayoutDimension(i4, layoutParams2.width);
        layoutParams2.height = obtainStyledAttributes.getLayoutDimension(i4, layoutParams2.height);
        this.f10755p = obtainStyledAttributes.getInt(R$styleable.ClassicsHeader_srlFinishDuration, this.f10755p);
        this.f10729y = obtainStyledAttributes.getBoolean(R$styleable.ClassicsHeader_srlEnableLastTime, this.f10729y);
        this.f10744e = C2904c.f7958f[obtainStyledAttributes.getInt(R$styleable.ClassicsHeader_srlClassicsSpinnerStyle, this.f10744e.f7959g)];
        int i5 = R$styleable.ClassicsHeader_srlDrawableArrow;
        if (obtainStyledAttributes.hasValue(i5)) {
            this.f10747h.setImageDrawable(obtainStyledAttributes.getDrawable(i5));
        } else if (this.f10747h.getDrawable() == null) {
            C2907a c2907a = new C2907a();
            this.f10750k = c2907a;
            c2907a.f7977c.setColor(-10066330);
            this.f10747h.setImageDrawable(this.f10750k);
        }
        int i6 = R$styleable.ClassicsHeader_srlDrawableProgress;
        if (obtainStyledAttributes.hasValue(i6)) {
            this.f10748i.setImageDrawable(obtainStyledAttributes.getDrawable(i6));
        } else if (this.f10748i.getDrawable() == null) {
            C2909c c2909c = new C2909c();
            this.f10751l = c2909c;
            c2909c.f7977c.setColor(-10066330);
            this.f10748i.setImageDrawable(this.f10751l);
        }
        if (obtainStyledAttributes.hasValue(R$styleable.ClassicsHeader_srlTextSizeTitle)) {
            this.f10746g.setTextSize(0, obtainStyledAttributes.getDimensionPixelSize(r4, InterpolatorC2917b.m3382c(16.0f)));
        }
        if (obtainStyledAttributes.hasValue(R$styleable.ClassicsHeader_srlTextSizeTime)) {
            this.f10726v.setTextSize(0, obtainStyledAttributes.getDimensionPixelSize(r4, InterpolatorC2917b.m3382c(12.0f)));
        }
        int i7 = R$styleable.ClassicsHeader_srlPrimaryColor;
        if (obtainStyledAttributes.hasValue(i7)) {
            m4632s(obtainStyledAttributes.getColor(i7, 0));
        }
        int i8 = R$styleable.ClassicsHeader_srlAccentColor;
        if (obtainStyledAttributes.hasValue(i8)) {
            int color = obtainStyledAttributes.getColor(i8, 0);
            this.f10726v.setTextColor((16777215 & color) | (-872415232));
            super.mo4629r(color);
        }
        int i9 = R$styleable.ClassicsHeader_srlTextPulling;
        if (obtainStyledAttributes.hasValue(i9)) {
            this.f10730z = obtainStyledAttributes.getString(i9);
        } else {
            this.f10730z = context.getString(R$string.srl_header_pulling);
        }
        int i10 = R$styleable.ClassicsHeader_srlTextLoading;
        if (obtainStyledAttributes.hasValue(i10)) {
            this.f10718B = obtainStyledAttributes.getString(i10);
        } else {
            this.f10718B = context.getString(R$string.srl_header_loading);
        }
        int i11 = R$styleable.ClassicsHeader_srlTextRelease;
        if (obtainStyledAttributes.hasValue(i11)) {
            this.f10719C = obtainStyledAttributes.getString(i11);
        } else {
            this.f10719C = context.getString(R$string.srl_header_release);
        }
        int i12 = R$styleable.ClassicsHeader_srlTextFinish;
        if (obtainStyledAttributes.hasValue(i12)) {
            this.f10720D = obtainStyledAttributes.getString(i12);
        } else {
            this.f10720D = context.getString(R$string.srl_header_finish);
        }
        int i13 = R$styleable.ClassicsHeader_srlTextFailed;
        if (obtainStyledAttributes.hasValue(i13)) {
            this.f10721E = obtainStyledAttributes.getString(i13);
        } else {
            this.f10721E = context.getString(R$string.srl_header_failed);
        }
        int i14 = R$styleable.ClassicsHeader_srlTextSecondary;
        if (obtainStyledAttributes.hasValue(i14)) {
            this.f10723G = obtainStyledAttributes.getString(i14);
        } else {
            this.f10723G = context.getString(R$string.srl_header_secondary);
        }
        int i15 = R$styleable.ClassicsHeader_srlTextRefreshing;
        if (obtainStyledAttributes.hasValue(i15)) {
            this.f10717A = obtainStyledAttributes.getString(i15);
        } else {
            this.f10717A = context.getString(R$string.srl_header_refreshing);
        }
        int i16 = R$styleable.ClassicsHeader_srlTextUpdate;
        if (obtainStyledAttributes.hasValue(i16)) {
            this.f10722F = obtainStyledAttributes.getString(i16);
        } else {
            this.f10722F = context.getString(R$string.srl_header_update);
        }
        this.f10728x = new SimpleDateFormat(this.f10722F, Locale.getDefault());
        obtainStyledAttributes.recycle();
        imageView2.animate().setInterpolator(null);
        textView.setVisibility(this.f10729y ? 0 : 8);
        this.f10746g.setText(isInEditMode() ? this.f10717A : this.f10730z);
        if (isInEditMode()) {
            imageView.setVisibility(8);
        } else {
            imageView2.setVisibility(8);
        }
        try {
            if ((context instanceof FragmentActivity) && (supportFragmentManager = ((FragmentActivity) context).getSupportFragmentManager()) != null && (fragments = supportFragmentManager.getFragments()) != null && fragments.size() > 0) {
                m4630t(new Date());
                return;
            }
        } catch (Throwable th) {
            th.printStackTrace();
        }
        this.f10724t += context.getClass().getName();
        this.f10727w = context.getSharedPreferences("ClassicsHeader", 0);
        m4630t(new Date(this.f10727w.getLong(this.f10724t, System.currentTimeMillis())));
    }
}
