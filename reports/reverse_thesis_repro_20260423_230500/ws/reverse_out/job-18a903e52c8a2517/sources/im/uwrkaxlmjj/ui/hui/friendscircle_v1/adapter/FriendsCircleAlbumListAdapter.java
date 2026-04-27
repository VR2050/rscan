package im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter;

import android.app.Activity;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import androidx.recyclerview.widget.GridLayoutManager;
import com.bjz.comm.net.bean.RespFcAlbumListBean;
import com.bjz.comm.net.utils.HttpUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.hui.adapter.SmartViewHolder;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.glide.GlideUtils;
import im.uwrkaxlmjj.ui.hviews.dialogs.Util;
import java.util.Collection;
import java.util.Iterator;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FriendsCircleAlbumListAdapter extends BaseFcAdapter<RespFcAlbumListBean> {
    private final Activity mActivity;
    private final int screenWidth;

    public FriendsCircleAlbumListAdapter(Collection<RespFcAlbumListBean> collection, int layoutId, AdapterView.OnItemClickListener listener, Activity mActivity) {
        super(collection, layoutId, listener);
        this.mActivity = mActivity;
        this.screenWidth = Util.getScreenWidth(mActivity);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public SmartViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View itemView = LayoutInflater.from(parent.getContext()).inflate(this.mLayoutId, parent, false);
        return new SmartViewHolder(itemView, this.mListener);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter
    public void onBindViewHolder(SmartViewHolder holder, RespFcAlbumListBean model, int position) {
        RelativeLayout rl_item_fc_album_list = (RelativeLayout) holder.itemView.findViewById(R.attr.rl_item_fc_album_list);
        GridLayoutManager.LayoutParams lp = (GridLayoutManager.LayoutParams) rl_item_fc_album_list.getLayoutParams();
        lp.width = ((int) (this.screenWidth - Util.dp2px(this.mActivity, 40.0f))) / 3;
        lp.height = lp.width;
        lp.bottomMargin = AndroidUtilities.dp(2.0f);
        rl_item_fc_album_list.setLayoutParams(lp);
        ImageView iv_fc_img_thumb = (ImageView) holder.itemView.findViewById(R.attr.iv_fc_img_thumb);
        if (model != null && !TextUtils.isEmpty(model.getThum())) {
            GlideUtils.getInstance().load(HttpUtils.getInstance().getDownloadFileUrl() + model.getThum(), this.mActivity, iv_fc_img_thumb, R.drawable.fc_default_pic);
        }
        ImageView iv_play_button = (ImageView) holder.itemView.findViewById(R.attr.iv_play_button);
        iv_play_button.setVisibility(model.getExt() == 2 ? 0 : 8);
    }

    public void removeItemByForumID(long forumID) {
        if (this.mList != null && this.mList.size() > 0) {
            Iterator<RespFcAlbumListBean> iterator = this.mList.iterator();
            int i = 0;
            int startIndex = -1;
            int count = 0;
            while (iterator.hasNext()) {
                if (iterator.next().getMainID() == forumID) {
                    iterator.remove();
                    if (startIndex == -1) {
                        startIndex = i;
                    }
                    count++;
                }
                i++;
            }
            if (startIndex != -1 && count > 0) {
                notifyItemRangeRemoved(startIndex, count);
            }
        }
    }
}
