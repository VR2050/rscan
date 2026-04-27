package im.uwrkaxlmjj.ui.hcells;

import android.content.Context;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.glide.GlideUtils;
import java.util.ArrayList;
import java.util.Collections;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PhotoCell extends RelativeLayout implements View.OnClickListener {
    private Context context;
    private View divider;
    private ImageView ivPic1;
    private ImageView ivPic2;
    private ImageView ivPic3;
    private ImageView ivPic4;
    private OnPhotoCellClickListener listener;
    private TextView tvPhotoCellName;
    private ArrayList<String> urls;

    public interface OnPhotoCellClickListener {
        void onPhotoClick(ImageView imageView, int i, String str);
    }

    public PhotoCell(Context context) {
        this(context, null);
    }

    public PhotoCell(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public PhotoCell(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        initCell(context);
    }

    @Override // android.widget.RelativeLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
    }

    private void initCell(Context context) {
        this.context = context;
        LayoutInflater.from(context).inflate(R.layout.item_photo_cell, this);
        TextView textView = (TextView) findViewById(R.attr.tv_photo_cell_name);
        this.tvPhotoCellName = textView;
        textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.tvPhotoCellName.setTextSize(14.0f);
        this.tvPhotoCellName.setGravity(LocaleController.isRTL ? 5 : 3);
        this.divider = findViewById(R.attr.divider);
        this.ivPic1 = (ImageView) findViewById(R.attr.iv_pic1);
        this.ivPic2 = (ImageView) findViewById(R.attr.iv_pic2);
        this.ivPic3 = (ImageView) findViewById(R.attr.iv_pic3);
        this.ivPic4 = (ImageView) findViewById(R.attr.iv_pic4);
    }

    public void setData(ArrayList<String> urls) {
        this.ivPic1.setVisibility(8);
        this.ivPic2.setVisibility(8);
        this.ivPic3.setVisibility(8);
        this.ivPic4.setVisibility(8);
        if (urls != null && urls.size() > 0) {
            Collections.reverse(urls);
            this.urls = urls;
            for (int i = 0; i < urls.size(); i++) {
                if (i == 0) {
                    this.ivPic1.setOnClickListener(this);
                    this.ivPic1.setVisibility(TextUtils.isEmpty(urls.get(i)) ? 8 : 0);
                    GlideUtils.getInstance().load(urls.get(i), this.context, this.ivPic1, R.drawable.fc_default_pic);
                } else if (i == 1) {
                    this.ivPic2.setOnClickListener(this);
                    this.ivPic2.setVisibility(TextUtils.isEmpty(urls.get(i)) ? 8 : 0);
                    GlideUtils.getInstance().load(urls.get(i), this.context, this.ivPic2, R.drawable.fc_default_pic);
                } else if (i == 2) {
                    this.ivPic3.setOnClickListener(this);
                    this.ivPic3.setVisibility(TextUtils.isEmpty(urls.get(i)) ? 8 : 0);
                    GlideUtils.getInstance().load(urls.get(i), this.context, this.ivPic3, R.drawable.fc_default_pic);
                } else if (i == 3) {
                    this.ivPic4.setOnClickListener(this);
                    this.ivPic4.setVisibility(TextUtils.isEmpty(urls.get(i)) ? 8 : 0);
                    GlideUtils.getInstance().load(urls.get(i), this.context, this.ivPic4, R.drawable.fc_default_pic);
                }
            }
        }
    }

    public void setText(String name, boolean needDivider) {
        TextView textView = this.tvPhotoCellName;
        if (textView != null) {
            textView.setText(TextUtils.isEmpty(name) ? "" : name);
        }
        View view = this.divider;
        if (view != null) {
            view.setVisibility(needDivider ? 0 : 8);
        }
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View v) {
        switch (v.getId()) {
            case R.attr.iv_pic1 /* 2131296825 */:
                if (this.listener != null && this.urls.size() >= 1) {
                    this.listener.onPhotoClick(this.ivPic1, 0, this.urls.get(0));
                    break;
                }
                break;
            case R.attr.iv_pic2 /* 2131296826 */:
                if (this.listener != null && this.urls.size() >= 2) {
                    this.listener.onPhotoClick(this.ivPic2, 1, this.urls.get(1));
                    break;
                }
                break;
            case R.attr.iv_pic3 /* 2131296827 */:
                if (this.listener != null && this.urls.size() >= 3) {
                    this.listener.onPhotoClick(this.ivPic3, 2, this.urls.get(2));
                    break;
                }
                break;
            case R.attr.iv_pic4 /* 2131296828 */:
                if (this.listener != null && this.urls.size() >= 4) {
                    this.listener.onPhotoClick(this.ivPic4, 3, this.urls.get(3));
                    break;
                }
                break;
        }
    }

    public void setListener(OnPhotoCellClickListener listener) {
        this.listener = listener;
    }
}
