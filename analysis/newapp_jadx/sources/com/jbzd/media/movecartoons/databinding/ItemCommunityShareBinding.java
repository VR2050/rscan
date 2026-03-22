package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemCommunityShareBinding implements ViewBinding {

    @NonNull
    public final ImageView itvUserdetailCollectionCover;

    @NonNull
    public final ImageTextView itvUserdetailCollectionName;

    @NonNull
    public final ImageTextView itvUserdetailCollectionPlaynumber;

    @NonNull
    private final LinearLayout rootView;

    private ItemCommunityShareBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2) {
        this.rootView = linearLayout;
        this.itvUserdetailCollectionCover = imageView;
        this.itvUserdetailCollectionName = imageTextView;
        this.itvUserdetailCollectionPlaynumber = imageTextView2;
    }

    @NonNull
    public static ItemCommunityShareBinding bind(@NonNull View view) {
        int i2 = R.id.itv_userdetail_collection_cover;
        ImageView imageView = (ImageView) view.findViewById(R.id.itv_userdetail_collection_cover);
        if (imageView != null) {
            i2 = R.id.itv_userdetail_collection_name;
            ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_userdetail_collection_name);
            if (imageTextView != null) {
                i2 = R.id.itv_userdetail_collection_playnumber;
                ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.itv_userdetail_collection_playnumber);
                if (imageTextView2 != null) {
                    return new ItemCommunityShareBinding((LinearLayout) view, imageView, imageTextView, imageTextView2);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemCommunityShareBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemCommunityShareBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_community_share, viewGroup, false);
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
