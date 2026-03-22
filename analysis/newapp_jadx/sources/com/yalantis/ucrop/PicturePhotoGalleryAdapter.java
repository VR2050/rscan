package com.yalantis.ucrop;

import android.content.Context;
import android.graphics.Bitmap;
import android.net.Uri;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import com.yalantis.ucrop.callback.BitmapLoadCallback;
import com.yalantis.ucrop.model.CutInfo;
import com.yalantis.ucrop.model.ExifInfo;
import com.yalantis.ucrop.util.BitmapLoadUtils;
import com.yalantis.ucrop.util.MimeType;
import com.yalantis.ucrop.util.SdkUtils;
import java.io.File;
import java.util.List;

/* loaded from: classes2.dex */
public class PicturePhotoGalleryAdapter extends RecyclerView.Adapter<ViewHolder> {
    private Context context;
    private List<CutInfo> list;
    private OnItemClickListener listener;
    private LayoutInflater mInflater;
    private final int maxImageWidth = 200;
    private final int maxImageHeight = 220;

    public interface OnItemClickListener {
        void onItemClick(int i2, View view);
    }

    public static class ViewHolder extends RecyclerView.ViewHolder {
        public ImageView iv_dot;
        public ImageView mIvPhoto;
        public ImageView mIvVideo;
        public TextView tvGif;

        public ViewHolder(View view) {
            super(view);
            this.mIvPhoto = (ImageView) view.findViewById(C4161R.id.iv_photo);
            this.mIvVideo = (ImageView) view.findViewById(C4161R.id.iv_video);
            this.iv_dot = (ImageView) view.findViewById(C4161R.id.iv_dot);
            this.tvGif = (TextView) view.findViewById(C4161R.id.tv_gif);
        }
    }

    public PicturePhotoGalleryAdapter(Context context, List<CutInfo> list) {
        this.mInflater = LayoutInflater.from(context);
        this.context = context;
        this.list = list;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        List<CutInfo> list = this.list;
        if (list != null) {
            return list.size();
        }
        return 0;
    }

    public void setData(List<CutInfo> list) {
        this.list = list;
        notifyDataSetChanged();
    }

    public void setOnItemClickListener(OnItemClickListener onItemClickListener) {
        this.listener = onItemClickListener;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(final ViewHolder viewHolder, int i2) {
        CutInfo cutInfo = this.list.get(i2);
        String path = cutInfo != null ? cutInfo.getPath() : "";
        if (cutInfo.isCut()) {
            viewHolder.iv_dot.setVisibility(0);
            viewHolder.iv_dot.setImageResource(C4161R.drawable.ucrop_oval_true);
        } else {
            viewHolder.iv_dot.setVisibility(4);
        }
        if (MimeType.isHasVideo(cutInfo.getMimeType())) {
            viewHolder.mIvPhoto.setVisibility(8);
            viewHolder.mIvVideo.setVisibility(0);
            viewHolder.mIvVideo.setImageResource(C4161R.drawable.ucrop_ic_default_video);
        } else {
            viewHolder.mIvPhoto.setVisibility(0);
            viewHolder.mIvVideo.setVisibility(8);
            Uri parse = (SdkUtils.isQ() || MimeType.isHttp(path)) ? Uri.parse(path) : Uri.fromFile(new File(path));
            viewHolder.tvGif.setVisibility(MimeType.isGif(cutInfo.getMimeType()) ? 0 : 8);
            BitmapLoadUtils.decodeBitmapInBackground(this.context, parse, cutInfo.getHttpOutUri(), 200, 220, new BitmapLoadCallback() { // from class: com.yalantis.ucrop.PicturePhotoGalleryAdapter.1
                @Override // com.yalantis.ucrop.callback.BitmapLoadCallback
                public void onBitmapLoaded(@NonNull Bitmap bitmap, @NonNull ExifInfo exifInfo, @NonNull String str, @Nullable String str2) {
                    ImageView imageView = viewHolder.mIvPhoto;
                    if (imageView == null || bitmap == null) {
                        return;
                    }
                    imageView.setImageBitmap(bitmap);
                }

                @Override // com.yalantis.ucrop.callback.BitmapLoadCallback
                public void onFailure(@NonNull Exception exc) {
                    ImageView imageView = viewHolder.mIvPhoto;
                    if (imageView != null) {
                        imageView.setImageResource(C4161R.color.ucrop_color_ba3);
                    }
                }
            });
            viewHolder.itemView.setOnClickListener(new View.OnClickListener() { // from class: com.yalantis.ucrop.PicturePhotoGalleryAdapter.2
                @Override // android.view.View.OnClickListener
                public void onClick(View view) {
                    if (PicturePhotoGalleryAdapter.this.listener != null) {
                        PicturePhotoGalleryAdapter.this.listener.onItemClick(viewHolder.getAdapterPosition(), view);
                    }
                }
            });
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public ViewHolder onCreateViewHolder(ViewGroup viewGroup, int i2) {
        return new ViewHolder(this.mInflater.inflate(C4161R.layout.ucrop_picture_gf_adapter_edit_list, viewGroup, false));
    }
}
