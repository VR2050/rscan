package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.SeekBar;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogAutoPageBinding implements ViewBinding {

    @NonNull
    public final ImageView ivPosttypeCancel;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final SeekBar seekparAutoPage;

    @NonNull
    public final TextView tvAutoPageEnd;

    @NonNull
    public final TextView tvAutoPageStart;

    @NonNull
    public final TextView tvAutopageTitle;

    private DialogAutoPageBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull SeekBar seekBar, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = linearLayout;
        this.ivPosttypeCancel = imageView;
        this.seekparAutoPage = seekBar;
        this.tvAutoPageEnd = textView;
        this.tvAutoPageStart = textView2;
        this.tvAutopageTitle = textView3;
    }

    @NonNull
    public static DialogAutoPageBinding bind(@NonNull View view) {
        int i2 = R.id.iv_posttype_cancel;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_posttype_cancel);
        if (imageView != null) {
            i2 = R.id.seekpar_auto_page;
            SeekBar seekBar = (SeekBar) view.findViewById(R.id.seekpar_auto_page);
            if (seekBar != null) {
                i2 = R.id.tv_auto_page_end;
                TextView textView = (TextView) view.findViewById(R.id.tv_auto_page_end);
                if (textView != null) {
                    i2 = R.id.tv_auto_page_start;
                    TextView textView2 = (TextView) view.findViewById(R.id.tv_auto_page_start);
                    if (textView2 != null) {
                        i2 = R.id.tv_autopage_title;
                        TextView textView3 = (TextView) view.findViewById(R.id.tv_autopage_title);
                        if (textView3 != null) {
                            return new DialogAutoPageBinding((LinearLayout) view, imageView, seekBar, textView, textView2, textView3);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogAutoPageBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogAutoPageBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_auto_page, viewGroup, false);
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
