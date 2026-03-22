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
public final class ItemPostblockBinding implements ViewBinding {

    @NonNull
    public final TextView itvPostuserFollow;

    @NonNull
    public final ImageView ivPostblock;

    @NonNull
    public final LinearLayout llPostblock;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvPostblockClick;

    @NonNull
    public final TextView tvPostblockFollow;

    @NonNull
    public final TextView tvPostblockName;

    private ItemPostblockBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout2, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = linearLayout;
        this.itvPostuserFollow = textView;
        this.ivPostblock = imageView;
        this.llPostblock = linearLayout2;
        this.tvPostblockClick = textView2;
        this.tvPostblockFollow = textView3;
        this.tvPostblockName = textView4;
    }

    @NonNull
    public static ItemPostblockBinding bind(@NonNull View view) {
        int i2 = R.id.itv_postuser_follow;
        TextView textView = (TextView) view.findViewById(R.id.itv_postuser_follow);
        if (textView != null) {
            i2 = R.id.iv_postblock;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_postblock);
            if (imageView != null) {
                LinearLayout linearLayout = (LinearLayout) view;
                i2 = R.id.tv_postblock_click;
                TextView textView2 = (TextView) view.findViewById(R.id.tv_postblock_click);
                if (textView2 != null) {
                    i2 = R.id.tv_postblock_follow;
                    TextView textView3 = (TextView) view.findViewById(R.id.tv_postblock_follow);
                    if (textView3 != null) {
                        i2 = R.id.tv_postblock_name;
                        TextView textView4 = (TextView) view.findViewById(R.id.tv_postblock_name);
                        if (textView4 != null) {
                            return new ItemPostblockBinding(linearLayout, textView, imageView, linearLayout, textView2, textView3, textView4);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemPostblockBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemPostblockBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_postblock, viewGroup, false);
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
