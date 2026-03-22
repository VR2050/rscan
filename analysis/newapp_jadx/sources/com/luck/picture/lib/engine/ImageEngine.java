package com.luck.picture.lib.engine;

import android.content.Context;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import com.luck.picture.lib.listener.OnImageCompleteCallback;
import com.luck.picture.lib.widget.longimage.SubsamplingScaleImageView;

/* loaded from: classes2.dex */
public interface ImageEngine {
    void loadAsGifImage(@NonNull Context context, @NonNull String str, @NonNull ImageView imageView);

    void loadFolderImage(@NonNull Context context, @NonNull String str, @NonNull ImageView imageView);

    void loadGridImage(@NonNull Context context, @NonNull String str, @NonNull ImageView imageView);

    void loadImage(@NonNull Context context, @NonNull String str, @NonNull ImageView imageView);

    @Deprecated
    void loadImage(@NonNull Context context, @NonNull String str, @NonNull ImageView imageView, SubsamplingScaleImageView subsamplingScaleImageView);

    void loadImage(@NonNull Context context, @NonNull String str, @NonNull ImageView imageView, SubsamplingScaleImageView subsamplingScaleImageView, OnImageCompleteCallback onImageCompleteCallback);
}
