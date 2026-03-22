package com.luck.picture.lib.adapter;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.recyclerview.widget.RecyclerView;
import com.luck.picture.lib.C3979R;
import com.luck.picture.lib.adapter.PictureAlbumDirectoryAdapter;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.engine.ImageEngine;
import com.luck.picture.lib.entity.LocalMediaFolder;
import com.luck.picture.lib.listener.OnAlbumItemClickListener;
import com.luck.picture.lib.style.PictureParameterStyle;
import com.luck.picture.lib.style.PictureSelectorUIStyle;
import com.luck.picture.lib.tools.AttrsUtils;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class PictureAlbumDirectoryAdapter extends RecyclerView.Adapter<ViewHolder> {
    private int chooseMode;
    private List<LocalMediaFolder> folders = new ArrayList();
    private OnAlbumItemClickListener onAlbumItemClickListener;

    public static class ViewHolder extends RecyclerView.ViewHolder {
        public ImageView ivFirstImage;
        public TextView tvFolderName;
        public TextView tvSign;

        public ViewHolder(View view) {
            super(view);
            this.ivFirstImage = (ImageView) view.findViewById(C3979R.id.first_image);
            this.tvFolderName = (TextView) view.findViewById(C3979R.id.tv_folder_name);
            TextView textView = (TextView) view.findViewById(C3979R.id.tv_sign);
            this.tvSign = textView;
            PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
            if (pictureSelectorUIStyle != null) {
                int i2 = pictureSelectorUIStyle.picture_album_checkDotStyle;
                if (i2 != 0) {
                    textView.setBackgroundResource(i2);
                }
                int i3 = PictureSelectionConfig.uiStyle.picture_album_textColor;
                if (i3 != 0) {
                    this.tvFolderName.setTextColor(i3);
                }
                int i4 = PictureSelectionConfig.uiStyle.picture_album_textSize;
                if (i4 > 0) {
                    this.tvFolderName.setTextSize(i4);
                    return;
                }
                return;
            }
            PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
            if (pictureParameterStyle == null) {
                this.tvSign.setBackground(AttrsUtils.getTypeValueDrawable(view.getContext(), C3979R.attr.picture_folder_checked_dot, C3979R.drawable.picture_orange_oval));
                int typeValueColor = AttrsUtils.getTypeValueColor(view.getContext(), C3979R.attr.picture_folder_textColor);
                if (typeValueColor != 0) {
                    this.tvFolderName.setTextColor(typeValueColor);
                }
                float typeValueSize = AttrsUtils.getTypeValueSize(view.getContext(), C3979R.attr.picture_folder_textSize);
                if (typeValueSize > 0.0f) {
                    this.tvFolderName.setTextSize(0, typeValueSize);
                    return;
                }
                return;
            }
            int i5 = pictureParameterStyle.pictureFolderCheckedDotStyle;
            if (i5 != 0) {
                textView.setBackgroundResource(i5);
            }
            int i6 = PictureSelectionConfig.style.folderTextColor;
            if (i6 != 0) {
                this.tvFolderName.setTextColor(i6);
            }
            int i7 = PictureSelectionConfig.style.folderTextSize;
            if (i7 > 0) {
                this.tvFolderName.setTextSize(i7);
            }
        }
    }

    public PictureAlbumDirectoryAdapter(PictureSelectionConfig pictureSelectionConfig) {
        this.chooseMode = pictureSelectionConfig.chooseMode;
    }

    /* renamed from: a */
    public /* synthetic */ void m4534a(LocalMediaFolder localMediaFolder, int i2, View view) {
        if (this.onAlbumItemClickListener != null) {
            int size = this.folders.size();
            for (int i3 = 0; i3 < size; i3++) {
                this.folders.get(i3).setChecked(false);
            }
            localMediaFolder.setChecked(true);
            notifyDataSetChanged();
            this.onAlbumItemClickListener.onItemClick(i2, localMediaFolder.isCameraFolder(), localMediaFolder.getBucketId(), localMediaFolder.getName(), localMediaFolder.getData());
        }
    }

    public void bindFolderData(List<LocalMediaFolder> list) {
        if (list == null) {
            list = new ArrayList<>();
        }
        this.folders = list;
        notifyDataSetChanged();
    }

    public List<LocalMediaFolder> getFolderData() {
        List<LocalMediaFolder> list = this.folders;
        return list == null ? new ArrayList() : list;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        return this.folders.size();
    }

    public void setChooseMode(int i2) {
        this.chooseMode = i2;
    }

    public void setOnAlbumItemClickListener(OnAlbumItemClickListener onAlbumItemClickListener) {
        this.onAlbumItemClickListener = onAlbumItemClickListener;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(ViewHolder viewHolder, final int i2) {
        int i3;
        final LocalMediaFolder localMediaFolder = this.folders.get(i2);
        String name = localMediaFolder.getName();
        int imageNum = localMediaFolder.getImageNum();
        String firstImagePath = localMediaFolder.getFirstImagePath();
        boolean isChecked = localMediaFolder.isChecked();
        viewHolder.tvSign.setVisibility(localMediaFolder.getCheckedNum() > 0 ? 0 : 4);
        viewHolder.itemView.setSelected(isChecked);
        PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
        if (pictureSelectorUIStyle != null) {
            int i4 = pictureSelectorUIStyle.picture_album_backgroundStyle;
            if (i4 != 0) {
                viewHolder.itemView.setBackgroundResource(i4);
            }
        } else {
            PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
            if (pictureParameterStyle != null && (i3 = pictureParameterStyle.pictureAlbumStyle) != 0) {
                viewHolder.itemView.setBackgroundResource(i3);
            }
        }
        if (this.chooseMode == PictureMimeType.ofAudio()) {
            viewHolder.ivFirstImage.setImageResource(C3979R.drawable.picture_audio_placeholder);
        } else {
            ImageEngine imageEngine = PictureSelectionConfig.imageEngine;
            if (imageEngine != null) {
                imageEngine.loadFolderImage(viewHolder.itemView.getContext(), firstImagePath, viewHolder.ivFirstImage);
            }
        }
        Context context = viewHolder.itemView.getContext();
        if (localMediaFolder.getOfAllType() != -1) {
            name = localMediaFolder.getOfAllType() == PictureMimeType.ofAudio() ? context.getString(C3979R.string.picture_all_audio) : context.getString(C3979R.string.picture_camera_roll);
        }
        viewHolder.tvFolderName.setText(context.getString(C3979R.string.picture_camera_roll_num, name, Integer.valueOf(imageNum)));
        viewHolder.itemView.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.h0.a
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PictureAlbumDirectoryAdapter.this.m4534a(localMediaFolder, i2, view);
            }
        });
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public ViewHolder onCreateViewHolder(ViewGroup viewGroup, int i2) {
        return new ViewHolder(LayoutInflater.from(viewGroup.getContext()).inflate(C3979R.layout.picture_album_folder_item, viewGroup, false));
    }
}
