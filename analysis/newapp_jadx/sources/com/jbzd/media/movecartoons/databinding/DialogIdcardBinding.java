package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogIdcardBinding implements ViewBinding {

    @NonNull
    public final TextView btnSaveCardid;

    @NonNull
    public final ImageView ivQrcodeCardid;

    @NonNull
    public final LinearLayout llCardInfo;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tvCode;

    @NonNull
    public final TextView tvSiteUrl;

    private DialogIdcardBinding(@NonNull FrameLayout frameLayout, @NonNull TextView textView, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = frameLayout;
        this.btnSaveCardid = textView;
        this.ivQrcodeCardid = imageView;
        this.llCardInfo = linearLayout;
        this.tvCode = textView2;
        this.tvSiteUrl = textView3;
    }

    @NonNull
    public static DialogIdcardBinding bind(@NonNull View view) {
        int i2 = R.id.btn_save_cardid;
        TextView textView = (TextView) view.findViewById(R.id.btn_save_cardid);
        if (textView != null) {
            i2 = R.id.iv_qrcode_cardid;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_qrcode_cardid);
            if (imageView != null) {
                i2 = R.id.ll_card_info;
                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_card_info);
                if (linearLayout != null) {
                    i2 = R.id.tv_code;
                    TextView textView2 = (TextView) view.findViewById(R.id.tv_code);
                    if (textView2 != null) {
                        i2 = R.id.tv_site_url;
                        TextView textView3 = (TextView) view.findViewById(R.id.tv_site_url);
                        if (textView3 != null) {
                            return new DialogIdcardBinding((FrameLayout) view, textView, imageView, linearLayout, textView2, textView3);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogIdcardBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogIdcardBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_idcard, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public FrameLayout getRoot() {
        return this.rootView;
    }
}
