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
public final class LsettingsItemBinding implements ViewBinding {

    @NonNull
    public final ImageView arrow;

    @NonNull
    public final ImageView ivIcon;

    @NonNull
    public final View line;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvRight;

    @NonNull
    public final TextView tvTitle;

    private LsettingsItemBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull View view, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = linearLayout;
        this.arrow = imageView;
        this.ivIcon = imageView2;
        this.line = view;
        this.tvRight = textView;
        this.tvTitle = textView2;
    }

    @NonNull
    public static LsettingsItemBinding bind(@NonNull View view) {
        int i2 = R.id.arrow;
        ImageView imageView = (ImageView) view.findViewById(R.id.arrow);
        if (imageView != null) {
            i2 = R.id.iv_icon;
            ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_icon);
            if (imageView2 != null) {
                i2 = R.id.line;
                View findViewById = view.findViewById(R.id.line);
                if (findViewById != null) {
                    i2 = R.id.tvRight;
                    TextView textView = (TextView) view.findViewById(R.id.tvRight);
                    if (textView != null) {
                        i2 = R.id.tvTitle;
                        TextView textView2 = (TextView) view.findViewById(R.id.tvTitle);
                        if (textView2 != null) {
                            return new LsettingsItemBinding((LinearLayout) view, imageView, imageView2, findViewById, textView, textView2);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static LsettingsItemBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static LsettingsItemBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.lsettings_item, viewGroup, false);
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
