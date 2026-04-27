package im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter;

import android.app.Activity;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import com.bjz.comm.net.bean.FcMediaBean;
import com.bjz.comm.net.utils.HttpUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.hui.adapter.SmartViewHolder;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.glide.GlideUtils;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcPhotosAdapter extends BaseFcAdapter<FcMediaBean> {
    private ArrayList<String> bigPicList;
    private Activity mContext;
    private OnPicClickListener mOnPicClickListener;
    private final int screenWidth;

    public interface OnPicClickListener {
        void onPicClick(View view, List<String> list, int i);
    }

    public FcPhotosAdapter(Collection<FcMediaBean> collection, Activity mContext, int layoutId, int screenWidth, OnPicClickListener listener, boolean flag) {
        super(collection, layoutId);
        this.bigPicList = new ArrayList<>();
        this.mContext = mContext;
        this.mOnPicClickListener = listener;
        this.flag = flag;
        this.screenWidth = screenWidth;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter
    public void onBindViewHolder(SmartViewHolder abrItem, FcMediaBean model, final int position) {
        String picName;
        ImageView item_icon = (ImageView) abrItem.itemView.findViewById(R.attr.item_icon);
        FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) item_icon.getLayoutParams();
        if (getItemCount() == 1) {
            lp.width = ((this.screenWidth - AndroidUtilities.dp(40.0f)) / 3) * 2;
            lp.height = (lp.width / 3) * 4;
            picName = model.getName();
        } else {
            lp.width = ((this.screenWidth - AndroidUtilities.dp(40.0f)) / 3) - AndroidUtilities.dp(2.0f);
            lp.height = lp.width;
            picName = model.getExt() == 3 ? model.getName() : model.getThum();
        }
        item_icon.setLayoutParams(lp);
        GlideUtils.getInstance().load(HttpUtils.getInstance().getDownloadFileUrl() + picName, this.mContext, item_icon, R.drawable.shape_fc_default_pic_bg);
        FcMediaBean fcMediaBean = (FcMediaBean) this.mList.get(position);
        if (fcMediaBean != null) {
            this.bigPicList.add(fcMediaBean.getName());
        }
        item_icon.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcPhotosAdapter.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (FcPhotosAdapter.this.mOnPicClickListener != null) {
                    FcPhotosAdapter.this.mOnPicClickListener.onPicClick(v, FcPhotosAdapter.this.bigPicList, position);
                }
            }
        });
    }
}
