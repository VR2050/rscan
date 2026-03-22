package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemVipGlBinding implements ViewBinding {

    /* renamed from: iv */
    @NonNull
    public final ImageView f10058iv;

    @NonNull
    public final TextView ivCenterPlayicon;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvDesc;

    private ItemVipGlBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = linearLayout;
        this.f10058iv = imageView;
        this.ivCenterPlayicon = textView;
        this.tvDesc = textView2;
    }

    @NonNull
    public static ItemVipGlBinding bind(@NonNull View view) {
        int i2 = R.id.f13001iv;
        ImageView imageView = (ImageView) view.findViewById(R.id.f13001iv);
        if (imageView != null) {
            i2 = R.id.iv_center_playicon;
            TextView textView = (TextView) view.findViewById(R.id.iv_center_playicon);
            if (textView != null) {
                i2 = R.id.tvDesc;
                TextView textView2 = (TextView) view.findViewById(R.id.tvDesc);
                if (textView2 != null) {
                    return new ItemVipGlBinding((LinearLayout) view, imageView, textView, textView2);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemVipGlBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemVipGlBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_vip_gl, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public LinearLayout getRoot() {
        return this.rootView;
    }
}
