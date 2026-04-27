package im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter;

import android.app.Activity;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import com.bjz.comm.net.bean.AvatarPhotoBean;
import com.bjz.comm.net.bean.FcLikeBean;
import com.bjz.comm.net.bean.FcUserInfoBean;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.utils.ShapeUtils;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.hui.adapter.SmartViewHolder;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.dialogs.Util;
import java.util.Collection;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcDetailLikedUserAdapter extends BaseFcAdapter<FcLikeBean> {
    private static final int ITEM_TYPE_ITEM = 0;
    private static final int ITEM_TYPE_LOAD_MORE;
    private static int itemType;
    private final FcItemActionClickListener listener;
    private final Activity mContext;
    private final int screenWidth;
    private SmartViewHolder smartViewHolder;
    private int spanCount;
    private int thumbUp;

    public FcDetailLikedUserAdapter(Activity context, Collection<FcLikeBean> collection, int layoutId, boolean flag, int thumbUp, FcItemActionClickListener listener) {
        super(collection, layoutId);
        this.spanCount = 8;
        this.flag = flag;
        this.mContext = context;
        this.thumbUp = thumbUp;
        this.listener = listener;
        this.screenWidth = Util.getScreenWidth(context);
    }

    static {
        itemType = 0;
        int i = 0 + 1;
        itemType = i;
        itemType = i + 1;
        ITEM_TYPE_LOAD_MORE = i;
    }

    public void setThumbUp(boolean isLike) {
        if (isLike) {
            this.thumbUp++;
        } else {
            this.thumbUp--;
        }
    }

    public int getThumbUp() {
        return this.thumbUp;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int position) {
        int itemCount = getItemCount();
        if (itemCount < this.thumbUp && position == itemCount - 1 && getItemCount() % this.spanCount == 0) {
            return ITEM_TYPE_LOAD_MORE;
        }
        return ITEM_TYPE_ITEM;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        int itemCount = super.getItemCount();
        if (itemCount < this.thumbUp) {
            int i = this.spanCount;
            if (itemCount % i == 1) {
                return itemCount - 1;
            }
            if (itemCount % i == 7) {
                return itemCount + 1;
            }
        }
        return itemCount;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public long getItemId(int position) {
        return position;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public SmartViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        if (viewType == ITEM_TYPE_LOAD_MORE) {
            MryTextView mryTextView = new MryTextView(this.mContext);
            mryTextView.setId(mryTextView.hashCode());
            mryTextView.setBackground(ShapeUtils.create(this.mContext.getResources().getColor(R.color.color_FFF5F5F5), AndroidUtilities.dp(5.0f)));
            mryTextView.setText("更多");
            FrameLayout.LayoutParams layoutParams = LayoutHelper.createFrame(40, 40.0f);
            layoutParams.topMargin = AndroidUtilities.dp(4.0f);
            layoutParams.bottomMargin = AndroidUtilities.dp(4.0f);
            mryTextView.setLayoutParams(layoutParams);
            mryTextView.setGravity(17);
            mryTextView.setTextAlignment(4);
            mryTextView.setTextColor(this.mContext.getResources().getColor(R.color.color_FFBCBCBC));
            mryTextView.setTextSize(12.0f);
            mryTextView.setPadding(AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f));
            Drawable drawable = this.mContext.getResources().getDrawable(R.drawable.ic_fc_arrow_down);
            drawable.setBounds(0, 0, 0, 0);
            mryTextView.setCompoundDrawablesWithIntrinsicBounds((Drawable) null, (Drawable) null, (Drawable) null, drawable);
            SmartViewHolder smartViewHolder = new SmartViewHolder(mryTextView, this.mListener);
            this.smartViewHolder = smartViewHolder;
            return smartViewHolder;
        }
        return new SmartViewHolder(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_fc_detail_liked_user, (ViewGroup) null), this.mListener);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter
    public void onBindViewHolder(SmartViewHolder viewHolder, final FcLikeBean model, final int position) {
        if (getItemViewType(position) == ITEM_TYPE_LOAD_MORE) {
            viewHolder.itemView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailLikedUserAdapter.1
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    if (FcDetailLikedUserAdapter.this.listener != null) {
                        FcDetailLikedUserAdapter.this.listener.onAction(v, FcDetailAdapter.Index_click_load_more_like, position, model);
                    }
                }
            });
            return;
        }
        View itemView = viewHolder.itemView;
        itemView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        BackupImageView ivUserAvatar = (BackupImageView) itemView.findViewById(R.attr.iv_user_avatar);
        ivUserAvatar.setRoundRadius(AndroidUtilities.dp(5.0f));
        FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) ivUserAvatar.getLayoutParams();
        lp.width = ((this.screenWidth - AndroidUtilities.dp(40.0f)) - (AndroidUtilities.dp(8.0f) * 7)) / 8;
        lp.height = lp.width;
        ivUserAvatar.setLayoutParams(lp);
        String imgTag = lp.width + "_" + lp.width;
        bindUserInfo(model.getCreator(), ivUserAvatar, itemView, imgTag, position);
    }

    private void bindUserInfo(final FcUserInfoBean fcUserInfoBean, BackupImageView ivUserAvatar, View itemView, String imgTag, final int position) {
        ivUserAvatar.setImageResource(R.drawable.shape_bg_item_fc_detail_user_avatar);
        if (fcUserInfoBean != null) {
            AvatarPhotoBean avatarPhotoBean = fcUserInfoBean.getPhoto();
            if (avatarPhotoBean != null) {
                int photoSize = avatarPhotoBean.getSmallPhotoSize();
                int localId = avatarPhotoBean.getSmallLocalId();
                long volumeId = avatarPhotoBean.getSmallVolumeId();
                if (photoSize != 0 && volumeId != 0 && avatarPhotoBean.getAccess_hash() != 0) {
                    TLRPC.TL_inputPeerUser inputPeer = new TLRPC.TL_inputPeerUser();
                    inputPeer.user_id = fcUserInfoBean.getUserId();
                    inputPeer.access_hash = fcUserInfoBean.getAccessHash();
                    ImageLocation imageLocation = new ImageLocation();
                    imageLocation.dc_id = 2;
                    imageLocation.photoPeer = inputPeer;
                    imageLocation.location = new TLRPC.TL_fileLocationToBeDeprecated();
                    imageLocation.location.local_id = localId;
                    imageLocation.location.volume_id = volumeId;
                    AvatarDrawable drawable = new AvatarDrawable();
                    drawable.setInfo(fcUserInfoBean.getUserId(), fcUserInfoBean.getFirstName(), fcUserInfoBean.getLastName());
                    ivUserAvatar.setImage(imageLocation, imgTag, drawable, imageLocation.photoPeer);
                    itemView.setTag(Integer.valueOf(fcUserInfoBean.getUserId()));
                }
            }
            ivUserAvatar.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailLikedUserAdapter.2
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    if (FcDetailLikedUserAdapter.this.listener != null) {
                        FcDetailLikedUserAdapter.this.listener.onAction(v, FcDetailAdapter.Index_click_avatar, position, fcUserInfoBean);
                    }
                }
            });
        }
    }
}
