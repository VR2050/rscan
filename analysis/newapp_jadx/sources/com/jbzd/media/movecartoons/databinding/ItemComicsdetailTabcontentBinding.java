package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemComicsdetailTabcontentBinding implements ViewBinding {

    @NonNull
    public final ShapeableImageView ivChapterCover;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tvChapterName;

    @NonNull
    public final TextView tvTablecontentCoin;

    @NonNull
    public final TextView tvTablecontentVip;

    @NonNull
    public final TextView tvTablecontentWatch;

    private ItemComicsdetailTabcontentBinding(@NonNull FrameLayout frameLayout, @NonNull ShapeableImageView shapeableImageView, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = frameLayout;
        this.ivChapterCover = shapeableImageView;
        this.tvChapterName = textView;
        this.tvTablecontentCoin = textView2;
        this.tvTablecontentVip = textView3;
        this.tvTablecontentWatch = textView4;
    }

    @NonNull
    public static ItemComicsdetailTabcontentBinding bind(@NonNull View view) {
        int i2 = R.id.iv_chapter_cover;
        ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_chapter_cover);
        if (shapeableImageView != null) {
            i2 = R.id.tv_chapter_name;
            TextView textView = (TextView) view.findViewById(R.id.tv_chapter_name);
            if (textView != null) {
                i2 = R.id.tv_tablecontent_coin;
                TextView textView2 = (TextView) view.findViewById(R.id.tv_tablecontent_coin);
                if (textView2 != null) {
                    i2 = R.id.tv_tablecontent_vip;
                    TextView textView3 = (TextView) view.findViewById(R.id.tv_tablecontent_vip);
                    if (textView3 != null) {
                        i2 = R.id.tv_tablecontent_watch;
                        TextView textView4 = (TextView) view.findViewById(R.id.tv_tablecontent_watch);
                        if (textView4 != null) {
                            return new ItemComicsdetailTabcontentBinding((FrameLayout) view, shapeableImageView, textView, textView2, textView3, textView4);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemComicsdetailTabcontentBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemComicsdetailTabcontentBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_comicsdetail_tabcontent, viewGroup, false);
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
