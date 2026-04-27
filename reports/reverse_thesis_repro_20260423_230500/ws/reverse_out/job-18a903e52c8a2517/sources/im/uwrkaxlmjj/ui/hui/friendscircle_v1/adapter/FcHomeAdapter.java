package im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter;

import android.app.Activity;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.style.ForegroundColorSpan;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewStub;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import androidx.fragment.app.FragmentActivity;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.bjz.comm.net.bean.AvatarPhotoBean;
import com.bjz.comm.net.bean.FcMediaBean;
import com.bjz.comm.net.bean.FcUserInfoBean;
import com.bjz.comm.net.bean.RespFcListBean;
import com.bjz.comm.net.bean.TopicBean;
import com.bjz.comm.net.utils.HttpUtils;
import com.preview.PhotoPreview;
import com.preview.interfaces.ImageLoader;
import com.preview.interfaces.OnLongClickListener;
import com.socks.library.KLog;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.hui.adapter.SmartViewHolder;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcPhotosAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.decoration.GridSpaceItemDecoration;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.glide.GlideUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcClickSpanListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.view.FcVideoPlayerView;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageDetailActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageMineActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.StringUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.TimeUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcCommMenuDialog;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.expandTextView.ExpandableTextView;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout.FlowLayout;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout.TagAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout.TagFlowLayout;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.dialogs.Util;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;
import org.json.JSONException;

/* JADX INFO: loaded from: classes5.dex */
public class FcHomeAdapter extends BaseFcAdapter<RespFcListBean> {
    private static final int ITEM_TYPE_BOTTOM;
    private static final int ITEM_TYPE_TEXT;
    private static final int ITEM_TYPE_TEXT_PHOTOS;
    private static final int ITEM_TYPE_TEXT_VIDEO;
    public static final int Index_click_follow;
    public static final int Index_click_like;
    public static final int Index_click_location;
    private static final int Index_click_more_operate;
    public static final int Index_click_pop_cancel_follow;
    public static final int Index_click_pop_delete;
    public static final int Index_click_pop_private;
    public static final int Index_click_pop_public;
    public static final int Index_click_pop_report;
    public static final int Index_click_pop_shield_item;
    public static final int Index_click_pop_shield_user;
    public static final int Index_click_reply;
    public static final int Index_download_photo;
    public static final int Index_download_video;
    private static int index;
    private static int itemType;
    private String TAG;
    private final TLRPC.User currentUser;
    private int currentUserId;
    private boolean isShowFollow;
    private boolean isShowReply;
    private FcItemActionClickListener listener;
    private Activity mContext;
    private int mFooterCount;
    private final int mGuid;
    private int mHeaderCount;
    private RespFcListBean operateModel;
    private int operatePosition;
    private FcCommMenuDialog othersFcOperateDialog;
    private FcCommMenuDialog ownFcOperateDialog;
    private int pageIndex;
    private PhotoPreview photoPreview;
    private final int screenWidth;
    public static final int Index_click_avatar = 0;
    private static final int ITEM_TYPE_HEADER = 0;

    static {
        index = 0;
        int i = 0 + 1;
        index = i;
        int i2 = i + 1;
        index = i2;
        Index_click_follow = i;
        int i3 = i2 + 1;
        index = i3;
        Index_click_more_operate = i2;
        int i4 = i3 + 1;
        index = i4;
        Index_download_photo = i3;
        int i5 = i4 + 1;
        index = i5;
        Index_download_video = i4;
        int i6 = i5 + 1;
        index = i6;
        Index_click_like = i5;
        int i7 = i6 + 1;
        index = i7;
        Index_click_reply = i6;
        int i8 = i7 + 1;
        index = i8;
        Index_click_location = i7;
        int i9 = i8 + 1;
        index = i9;
        Index_click_pop_public = i8;
        int i10 = i9 + 1;
        index = i10;
        Index_click_pop_private = i9;
        int i11 = i10 + 1;
        index = i11;
        Index_click_pop_delete = i10;
        int i12 = i11 + 1;
        index = i12;
        Index_click_pop_cancel_follow = i11;
        int i13 = i12 + 1;
        index = i13;
        Index_click_pop_shield_item = i12;
        int i14 = i13 + 1;
        index = i14;
        Index_click_pop_shield_user = i13;
        index = i14 + 1;
        Index_click_pop_report = i14;
        itemType = 0;
        int i15 = 0 + 1;
        itemType = i15;
        int i16 = i15 + 1;
        itemType = i16;
        ITEM_TYPE_BOTTOM = i15;
        int i17 = i16 + 1;
        itemType = i17;
        ITEM_TYPE_TEXT = i16;
        int i18 = i17 + 1;
        itemType = i18;
        ITEM_TYPE_TEXT_PHOTOS = i17;
        itemType = i18 + 1;
        ITEM_TYPE_TEXT_VIDEO = i18;
    }

    public FcHomeAdapter(Collection<RespFcListBean> collection, final Activity mContext, int guid, int pageIndex, FcItemActionClickListener listener) {
        super(collection, R.layout.item_fc_text);
        this.TAG = FcHomeAdapter.class.getSimpleName();
        this.mHeaderCount = 0;
        this.mFooterCount = 0;
        this.isShowReply = true;
        this.isShowFollow = true;
        this.pageIndex = 0;
        this.mContext = mContext;
        this.mGuid = guid;
        this.pageIndex = pageIndex;
        this.listener = listener;
        PhotoPreview photoPreview = new PhotoPreview((FragmentActivity) mContext, false, new ImageLoader() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter.1
            @Override // com.preview.interfaces.ImageLoader
            public void onLoadImage(int position, Object object, ImageView imageView) {
                KLog.d("-------大图-" + HttpUtils.getInstance().getDownloadFileUrl() + object);
                GlideUtils.getInstance().loadNOCentercrop(HttpUtils.getInstance().getDownloadFileUrl() + object, mContext, imageView, 0);
            }
        });
        this.photoPreview = photoPreview;
        photoPreview.setIndicatorType(0);
        this.photoPreview.setLongClickListener(new OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter.2
            @Override // com.preview.interfaces.OnLongClickListener
            public void onLongClick(FrameLayout rootView, Object path, int position) {
                FcHomeAdapter.this.setAction(rootView, FcHomeAdapter.Index_download_photo, position, path);
            }
        });
        this.screenWidth = Util.getScreenWidth(mContext);
        TLRPC.User currentUser = AccountInstance.getInstance(UserConfig.selectedAccount).getUserConfig().getCurrentUser();
        this.currentUser = currentUser;
        if (currentUser != null) {
            this.currentUserId = currentUser.id;
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public long getItemId(int position) {
        return position;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        return this.mList.size();
    }

    public long getEndListId() {
        if (this.mList.size() == 0) {
            return 0L;
        }
        return ((RespFcListBean) this.mList.get((this.mList.size() - 1) - getFooterSize())).getForumID();
    }

    private int getFooterSize() {
        RespFcListBean respFcListBean;
        return (this.mFooterCount <= 0 || getDataList().size() <= 1 || (respFcListBean = getDataList().get(getItemCount() - 1)) == null || respFcListBean.getForumID() != 0) ? 0 : 1;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int position) {
        int i = this.mHeaderCount;
        if (i != 0 && position < i) {
            return ITEM_TYPE_HEADER;
        }
        if (this.mFooterCount != 0 && position == getItemCount() - 1 && ((RespFcListBean) this.mList.get(position)).getForumID() == 0) {
            return ITEM_TYPE_BOTTOM;
        }
        if (getDataList() != null && position < getDataList().size()) {
            RespFcListBean respFcListBean = getDataList().get(position);
            if (respFcListBean != null) {
                ArrayList<FcMediaBean> medias = respFcListBean.getMedias();
                if (medias != null && medias.size() > 0) {
                    FcMediaBean media = medias.get(0);
                    if (media.getExt() == 1 || media.getExt() == 3) {
                        return ITEM_TYPE_TEXT_PHOTOS;
                    }
                    if (media.getExt() == 2) {
                        return ITEM_TYPE_TEXT_VIDEO;
                    }
                    return ITEM_TYPE_TEXT;
                }
                return ITEM_TYPE_TEXT;
            }
            return ITEM_TYPE_TEXT;
        }
        return ITEM_TYPE_TEXT;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public SmartViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        if (viewType == ITEM_TYPE_HEADER) {
            return new SmartViewHolder(LayoutInflater.from(parent.getContext()).inflate(R.layout.view_fc_home_header, (ViewGroup) null), this.mListener);
        }
        if (viewType == ITEM_TYPE_BOTTOM) {
            return new SmartViewHolder(LayoutInflater.from(parent.getContext()).inflate(R.layout.view_fc_footer, parent, false), this.mListener);
        }
        if (viewType == ITEM_TYPE_TEXT_PHOTOS) {
            return new SmartViewHolder(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_fc_text_photos, parent, false), this.mListener);
        }
        if (viewType == ITEM_TYPE_TEXT_VIDEO) {
            return new FcVideoViewHold(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_fc_text_video, parent, false), this.mListener);
        }
        return new SmartViewHolder(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_fc_text, parent, false), this.mListener);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter
    public void onBindViewHolder(SmartViewHolder viewHolder, final RespFcListBean model, final int position) {
        MryTextView tvPublishTime;
        MryTextView btnFollow;
        MryTextView btnLike;
        ImageView ivMoreOperate;
        TagFlowLayout viewTopics;
        MryTextView btnReply;
        MryTextView btnFollow2;
        RelativeLayout rlLocationInfo;
        MryTextView tvFcDetailLocation;
        int i;
        if (getItemViewType(position) != ITEM_TYPE_HEADER) {
            if (getItemViewType(position) == ITEM_TYPE_BOTTOM) {
                viewHolder.itemView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
                return;
            }
            viewHolder.itemView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            View itemView = viewHolder.itemView;
            BackupImageView ivUserAvatar = (BackupImageView) itemView.findViewById(R.attr.iv_user_avatar);
            ivUserAvatar.setRoundRadius(AndroidUtilities.dp(5.0f));
            MryTextView tvUserName = (MryTextView) itemView.findViewById(R.attr.tv_user_name);
            MryTextView tvPublishTime2 = (MryTextView) itemView.findViewById(R.attr.tv_publish_time);
            MryTextView btnFollow3 = (MryTextView) itemView.findViewById(R.attr.btn_follow);
            ImageView ivMoreOperate2 = (ImageView) itemView.findViewById(R.attr.iv_more_operate);
            MryTextView tvGender = (MryTextView) itemView.findViewById(R.attr.tv_gender);
            TagFlowLayout viewTopics2 = (TagFlowLayout) itemView.findViewById(R.attr.view_topics);
            MryTextView btnReply2 = (MryTextView) itemView.findViewById(R.attr.btn_reply);
            MryTextView btnLike2 = (MryTextView) itemView.findViewById(R.attr.btn_like);
            ViewStub viewStubLocation = (ViewStub) itemView.findViewById(R.attr.viewStub_location);
            ViewStub viewStubReply = (ViewStub) itemView.findViewById(R.attr.viewStub_reply);
            FcUserInfoBean fcUserInfoBean = model.getCreatorUser();
            if (fcUserInfoBean != null) {
                if (tvGender == null) {
                    viewTopics = viewTopics2;
                    btnReply = btnReply2;
                } else if (fcUserInfoBean.getSex() != 0) {
                    btnReply = btnReply2;
                    tvGender.setSelected(fcUserInfoBean.getSex() == 1);
                    if (fcUserInfoBean.getBirthday() > 0) {
                        viewTopics = viewTopics2;
                        Date date = new Date(((long) fcUserInfoBean.getBirthday()) * 1000);
                        int ageByBirthday = TimeUtils.getAgeByBirthday(date);
                        tvGender.setText(ageByBirthday > 0 ? String.valueOf(ageByBirthday) : "");
                        tvGender.setCompoundDrawablePadding(ageByBirthday > 0 ? AndroidUtilities.dp(2.0f) : 0);
                        i = 0;
                    } else {
                        viewTopics = viewTopics2;
                        tvGender.setText("");
                        i = 0;
                        tvGender.setCompoundDrawablePadding(0);
                    }
                    tvGender.setVisibility(i);
                } else {
                    viewTopics = viewTopics2;
                    btnReply = btnReply2;
                    tvGender.setVisibility(8);
                }
                if (this.currentUserId != 0 && fcUserInfoBean.getUserId() == this.currentUserId && this.currentUser != null) {
                    AvatarDrawable avatarDrawable = new AvatarDrawable(this.currentUser, true);
                    ivUserAvatar.setImage(ImageLocation.getForUser(this.currentUser, false), "40_40", avatarDrawable, this.currentUser);
                    tvUserName.setText(StringUtils.handleTextName(ContactsController.formatName(this.currentUser.first_name, this.currentUser.last_name), 12));
                    tvPublishTime = tvPublishTime2;
                    btnFollow = btnFollow3;
                    btnLike = btnLike2;
                    ivMoreOperate = ivMoreOperate2;
                } else {
                    AvatarPhotoBean avatarPhotoBean = fcUserInfoBean.getPhoto();
                    if (avatarPhotoBean == null) {
                        btnFollow = btnFollow3;
                        btnLike = btnLike2;
                        ivMoreOperate = ivMoreOperate2;
                        tvPublishTime = tvPublishTime2;
                    } else {
                        int photoSize = avatarPhotoBean.getSmallPhotoSize();
                        int localId = avatarPhotoBean.getSmallLocalId();
                        btnLike = btnLike2;
                        ivMoreOperate = ivMoreOperate2;
                        long volumeId = avatarPhotoBean.getSmallVolumeId();
                        if (photoSize == 0 || volumeId == 0 || avatarPhotoBean.getAccess_hash() == 0) {
                            btnFollow = btnFollow3;
                            tvPublishTime = tvPublishTime2;
                        } else {
                            TLRPC.TL_inputPeerUser inputPeer = new TLRPC.TL_inputPeerUser();
                            inputPeer.user_id = fcUserInfoBean.getUserId();
                            tvPublishTime = tvPublishTime2;
                            btnFollow = btnFollow3;
                            inputPeer.access_hash = fcUserInfoBean.getAccessHash();
                            ImageLocation imageLocation = new ImageLocation();
                            imageLocation.dc_id = 2;
                            imageLocation.photoPeer = inputPeer;
                            imageLocation.location = new TLRPC.TL_fileLocationToBeDeprecated();
                            imageLocation.location.local_id = localId;
                            imageLocation.location.volume_id = volumeId;
                            AvatarDrawable drawable = new AvatarDrawable();
                            ivUserAvatar.setImage(imageLocation, "40_40", drawable, inputPeer);
                        }
                    }
                    tvUserName.setText(StringUtils.handleTextName(ContactsController.formatName(fcUserInfoBean.getFirstName(), fcUserInfoBean.getLastName()), 12));
                }
            } else {
                tvPublishTime = tvPublishTime2;
                btnFollow = btnFollow3;
                btnLike = btnLike2;
                ivMoreOperate = ivMoreOperate2;
                viewTopics = viewTopics2;
                btnReply = btnReply2;
                tvGender.setVisibility(8);
            }
            ivUserAvatar.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter.4
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    FcHomeAdapter.this.setAction(v, FcHomeAdapter.Index_click_avatar, position, model);
                }
            });
            tvUserName.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter.5
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    FcHomeAdapter.this.setAction(v, FcHomeAdapter.Index_click_avatar, position, model);
                }
            });
            tvPublishTime.setText(TimeUtils.fcFormat2Date(model.getCreateAt()));
            tvPublishTime.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText7));
            ImageView ivMoreOperate3 = ivMoreOperate;
            ivMoreOperate3.setVisibility(0);
            ivMoreOperate3.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter.6
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    FcHomeAdapter.this.setAction(v, FcHomeAdapter.Index_click_more_operate, position, null);
                    if (model.getCreateBy() == UserConfig.getInstance(UserConfig.selectedAccount).getClientUserId()) {
                        FcHomeAdapter.this.popForOwnFc(model, position);
                    } else {
                        FcHomeAdapter.this.popForOthersFc(model, position, !r0.isShowFollow);
                    }
                }
            });
            if (!this.isShowFollow || model.getCreateBy() == UserConfig.getInstance(UserConfig.selectedAccount).getClientUserId()) {
                btnFollow2 = btnFollow;
                btnFollow2.setVisibility(8);
            } else {
                btnFollow2 = btnFollow;
                btnFollow2.setVisibility(0);
                btnFollow2.setSelected(model.isHasFollow());
                btnFollow2.setText(model.isHasFollow() ? "已关注" : "关注");
                btnFollow2.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter.7
                    @Override // android.view.View.OnClickListener
                    public void onClick(View v) {
                        if (model.isHasFollow()) {
                            FcHomeAdapter.this.setAction(v, FcHomeAdapter.Index_click_pop_cancel_follow, position, model);
                        } else {
                            FcHomeAdapter.this.setAction(v, FcHomeAdapter.Index_click_follow, position, model);
                        }
                    }
                });
            }
            setTextView(itemView, model);
            if (model.getMedias() != null && model.getMedias().size() > 0) {
                FcMediaBean fcMediaBean = model.getMedias().get(0);
                if (getItemViewType(position) == ITEM_TYPE_TEXT_PHOTOS) {
                    setPhotosView(itemView, model.getMedias());
                } else if (getItemViewType(position) == ITEM_TYPE_TEXT_VIDEO) {
                    setVideoView(itemView, fcMediaBean, position);
                }
            }
            setTopicsInfo(viewTopics, model.getTopic());
            final MryTextView btnLike3 = btnLike;
            btnLike3.setSelected(model.isHasThumb());
            btnLike3.setText(model.getThumbUp() > 0 ? String.valueOf(model.getThumbUp()) : "0");
            btnLike3.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter.8
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    btnLike3.setClickable(false);
                    FcHomeAdapter.this.setAction(v, FcHomeAdapter.Index_click_like, position, model);
                }
            });
            MryTextView btnReply3 = btnReply;
            btnReply3.setText(model.getCommentCount() > 0 ? String.valueOf(model.getCommentCount()) : "0");
            btnReply3.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter.9
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    FcHomeAdapter.this.onPresentDetailPage(model);
                }
            });
            String name = model.getLocationName();
            String city = model.getLocationCity();
            if (viewStubLocation != null && viewStubLocation.getParent() != null) {
                View inflate = viewStubLocation.inflate();
                rlLocationInfo = (RelativeLayout) inflate.findViewById(R.attr.rl_location_info);
                tvFcDetailLocation = (MryTextView) inflate.findViewById(R.attr.tv_fc_detail_location);
            } else {
                rlLocationInfo = (RelativeLayout) itemView.findViewById(R.attr.rl_location_info);
                tvFcDetailLocation = (MryTextView) itemView.findViewById(R.attr.tv_fc_detail_location);
            }
            if (!TextUtils.isEmpty(name) && !TextUtils.isEmpty(city) && !TextUtils.equals(name, city)) {
                name = city.replace("市", "") + "·" + name;
            }
            if (tvFcDetailLocation != null) {
                rlLocationInfo.setVisibility(TextUtils.isEmpty(name) ? 8 : 0);
                tvFcDetailLocation.setText(TextUtils.isEmpty(name) ? "" : name);
                tvFcDetailLocation.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter.10
                    @Override // android.view.View.OnClickListener
                    public void onClick(View v) {
                        FcHomeAdapter.this.setAction(v, FcHomeAdapter.Index_click_location, position, model);
                    }
                });
            }
            if (this.isShowReply) {
                setReplyView(itemView, viewStubReply, model, position);
            }
            itemView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter.11
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    if (FcHomeAdapter.this.listener != null) {
                        FcHomeAdapter.this.listener.onPresentFragment(new FcPageDetailActivity(model, FcHomeAdapter.this.pageIndex, false));
                    }
                }
            });
            return;
        }
        viewHolder.itemView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        BackupImageView ivUserAvatar2 = (BackupImageView) viewHolder.itemView.findViewById(R.attr.iv_user_avatar);
        ivUserAvatar2.setRoundRadius(AndroidUtilities.dp(5.0f));
        TLRPC.User currentUser = UserConfig.getInstance(UserConfig.selectedAccount).getCurrentUser();
        if (currentUser != null) {
            AvatarDrawable avatarDrawable2 = new AvatarDrawable(currentUser, true);
            ivUserAvatar2.setImage(ImageLocation.getForUser(currentUser, false), "40_40", avatarDrawable2, currentUser);
        }
        viewHolder.itemView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter.3
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (FcHomeAdapter.this.listener != null) {
                    FcHomeAdapter.this.listener.onPresentFragment(new FcPageMineActivity());
                }
            }
        });
    }

    private void setTextView(View itemView, RespFcListBean model) {
        ExpandableTextView tvContent = (ExpandableTextView) itemView.findViewById(R.attr.view_fc_text);
        tvContent.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        if (!TextUtils.isEmpty(model.getContent())) {
            tvContent.bind(model);
            tvContent.setEntitys(model.getEntitys());
            tvContent.setContent(model.getContent());
            tvContent.setLinkClickListener(new FcClickSpanListener(this.mContext, this.mGuid, this.listener));
            tvContent.setVisibility(0);
            return;
        }
        tvContent.setVisibility(8);
    }

    private void setPhotosView(View itemView, ArrayList<FcMediaBean> medias) {
        final RecyclerView rlFcDetailPhotos = (RecyclerView) itemView.findViewById(R.attr.rv_photos);
        rlFcDetailPhotos.setNestedScrollingEnabled(false);
        RelativeLayout.LayoutParams lp = (RelativeLayout.LayoutParams) rlFcDetailPhotos.getLayoutParams();
        if (medias.size() == 1) {
            lp.width = (((int) (this.screenWidth - Util.dp2px(this.mContext, 40.0f))) / 3) * 2;
            rlFcDetailPhotos.setLayoutManager(new LinearLayoutManager(this.mContext));
        } else if (medias.size() == 2 || medias.size() == 4) {
            rlFcDetailPhotos.setLayoutManager(new GridLayoutManager(this.mContext, 2));
            lp.width = (((int) (this.screenWidth - Util.dp2px(this.mContext, 40.0f))) / 3) * 2;
            if (rlFcDetailPhotos.getItemDecorationCount() == 0) {
                rlFcDetailPhotos.addItemDecoration(new GridSpaceItemDecoration(AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f), false));
            }
        } else {
            rlFcDetailPhotos.setLayoutManager(new GridLayoutManager(this.mContext, 3));
            lp.width = (int) (this.screenWidth - Util.dp2px(this.mContext, 40.0f));
            if (rlFcDetailPhotos.getItemDecorationCount() == 0) {
                rlFcDetailPhotos.addItemDecoration(new GridSpaceItemDecoration(AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f), false));
            }
        }
        lp.height = -2;
        rlFcDetailPhotos.setLayoutParams(lp);
        rlFcDetailPhotos.setAdapter(new FcPhotosAdapter(medias, this.mContext, R.layout.item_friends_circle_img, this.screenWidth, new FcPhotosAdapter.OnPicClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.-$$Lambda$FcHomeAdapter$wxwBhDgAz0eChkrV9BBj7rZE7js
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcPhotosAdapter.OnPicClickListener
            public final void onPicClick(View view, List list, int i) {
                this.f$0.lambda$setPhotosView$0$FcHomeAdapter(rlFcDetailPhotos, view, list, i);
            }
        }, true));
    }

    public /* synthetic */ void lambda$setPhotosView$0$FcHomeAdapter(RecyclerView rlFcDetailPhotos, View view, List dualist, int position1) {
        PhotoPreview photoPreview = this.photoPreview;
        if (photoPreview != null) {
            photoPreview.show(rlFcDetailPhotos, position1, (List<?>) dualist);
        }
    }

    private void setVideoView(View itemView, final FcMediaBean fcMediaBean, final int position) {
        final FcVideoPlayerView rlFcDetailVideo = (FcVideoPlayerView) itemView.findViewById(R.attr.view_video);
        String strThumb = HttpUtils.getInstance().getDownloadFileUrl() + fcMediaBean.getThum();
        rlFcDetailVideo.bind(HttpUtils.getInstance().getDownloadVideoFileUrl() + fcMediaBean.getName(), "");
        rlFcDetailVideo.getThumbImageView().setScaleType(ImageView.ScaleType.CENTER_CROP);
        float Ratio = (float) (((double) fcMediaBean.getWidth()) / fcMediaBean.getHeight());
        FrameLayout.LayoutParams params = (FrameLayout.LayoutParams) rlFcDetailVideo.getLayoutParams();
        if (Ratio > 1.0f) {
            params.width = AndroidUtilities.dp(240.0f);
            params.height = AndroidUtilities.dp(140.0f);
        } else {
            params.width = AndroidUtilities.dp(240.0f);
            params.height = AndroidUtilities.dp(320.0f);
        }
        rlFcDetailVideo.setLayoutParams(params);
        rlFcDetailVideo.setRatio(Ratio);
        GlideUtils.getInstance().load(strThumb, this.mContext, rlFcDetailVideo.getThumbImageView(), R.drawable.shape_fc_default_pic_bg);
        itemView.setTag(HttpUtils.getInstance().getDownloadFileUrl() + fcMediaBean.getName());
        rlFcDetailVideo.setListener(new FcVideoPlayerView.OnClickVideoContainerListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter.12
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.view.FcVideoPlayerView.OnClickVideoContainerListener
            public void onLongClick() {
                FcHomeAdapter.this.setAction(rlFcDetailVideo, FcHomeAdapter.Index_download_video, position, fcMediaBean.getName());
            }
        });
    }

    private void setTopicsInfo(TagFlowLayout viewTopics, ArrayList<TopicBean> topic) {
        viewTopics.removeAllViews();
        if (topic != null && topic.size() > 0) {
            viewTopics.setVisibility(0);
            viewTopics.setAdapter(new TagAdapter<TopicBean>(topic) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter.13
                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout.TagAdapter
                public View getView(FlowLayout parent, int position, TopicBean topicBean) {
                    MryTextView tv = (MryTextView) LayoutInflater.from(parent.getContext()).inflate(R.layout.item_fc_child_view_topics, (ViewGroup) null);
                    if (!TextUtils.isEmpty(topicBean.getTopicName())) {
                        SpannableStringBuilder stringBuilder = new SpannableStringBuilder(topicBean.getTopicName());
                        stringBuilder.insert(0, (CharSequence) "# ");
                        stringBuilder.setSpan(new ForegroundColorSpan(FcHomeAdapter.this.mContext.getResources().getColor(R.color.color_FF2ECEFD)), 0, 1, 18);
                        tv.setText(stringBuilder);
                    }
                    return tv;
                }
            });
        } else {
            viewTopics.setVisibility(8);
        }
    }

    private void setReplyView(View itemView, ViewStub viewStubReply, final RespFcListBean model, int position) {
        RecyclerView rvFcCommReply;
        RichTextView tvDoReply;
        if (model.getComments() != null) {
            if (viewStubReply != null && viewStubReply.getParent() != null) {
                viewStubReply.setLayoutResource(R.layout.layout_item_fc_detail_reply);
                View inflate = viewStubReply.inflate();
                rvFcCommReply = (RecyclerView) inflate.findViewById(R.attr.rv_fc_comm_reply);
                tvDoReply = (RichTextView) inflate.findViewById(R.attr.txt_comment);
            } else {
                rvFcCommReply = (RecyclerView) itemView.findViewById(R.attr.rv_fc_comm_reply);
                tvDoReply = (RichTextView) itemView.findViewById(R.attr.txt_comment);
            }
            if (rvFcCommReply != null && tvDoReply != null) {
                rvFcCommReply.setNestedScrollingEnabled(false);
                LinearLayoutManager layoutManager = new LinearLayoutManager(this.mContext) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter.14
                    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
                    public RecyclerView.LayoutParams generateDefaultLayoutParams() {
                        return new RecyclerView.LayoutParams(-1, -2);
                    }
                };
                layoutManager.setOrientation(1);
                rvFcCommReply.setLayoutManager(layoutManager);
                FcHomeItemReplyAdapter fcHomeItemReplyAdapter = new FcHomeItemReplyAdapter(this.mContext, model.getComments(), R.layout.item_fc_home_reply, true, position, model, this.pageIndex, this.mGuid, this.listener);
                rvFcCommReply.setAdapter(fcHomeItemReplyAdapter);
                rvFcCommReply.setVisibility(model.getComments().size() == 0 ? 8 : 0);
                tvDoReply.setText("评论一下…");
                tvDoReply.setTextColor(this.mContext.getResources().getColor(R.color.color_FFADADAD));
                tvDoReply.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter.15
                    @Override // android.view.View.OnClickListener
                    public void onClick(View v) {
                        FcHomeAdapter.this.onPresentDetailPage(model);
                    }
                });
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void popForOwnFc(RespFcListBean model, int position) {
        this.operateModel = model;
        this.operatePosition = position;
        if (this.ownFcOperateDialog == null) {
            List<String> titles = new ArrayList<>();
            titles.add(LocaleController.getString(R.string.firendscircle_delete_dynamic));
            List<Integer> icons = new ArrayList<>();
            icons.add(Integer.valueOf(R.drawable.my_fc_pop_delete));
            this.ownFcOperateDialog = new FcCommMenuDialog(this.mContext, titles, icons, Theme.getColor(Theme.key_windowBackgroundWhiteBlackText), new FcCommMenuDialog.RecyclerviewItemClickCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter.16
                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcCommMenuDialog.RecyclerviewItemClickCallBack
                public void onRecyclerviewItemClick(int index2) {
                    if (index2 == 0) {
                        FcHomeAdapter.this.setAction(null, FcHomeAdapter.Index_click_pop_delete, FcHomeAdapter.this.operatePosition, FcHomeAdapter.this.operateModel);
                    }
                }
            }, 1);
        }
        if (this.ownFcOperateDialog.isShowing()) {
            this.ownFcOperateDialog.dismiss();
        } else {
            this.ownFcOperateDialog.show();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void popForOthersFc(RespFcListBean model, int position, final boolean isShowCancelFollow) {
        if (this.mContext != null) {
            this.operateModel = model;
            this.operatePosition = position;
            if (this.othersFcOperateDialog == null) {
                List<String> titles = new ArrayList<>();
                if (isShowCancelFollow) {
                    titles.add("取消关注");
                }
                titles.add(LocaleController.getString(R.string.provicy_other_fc_item));
                titles.add(LocaleController.getString(R.string.ReportChat));
                List<Integer> icons = new ArrayList<>();
                if (isShowCancelFollow) {
                    icons.add(Integer.valueOf(R.id.fc_pop_cancel_followed));
                }
                icons.add(Integer.valueOf(R.id.fc_pop_shield));
                icons.add(Integer.valueOf(R.id.fc_pop_report));
                this.othersFcOperateDialog = new FcCommMenuDialog(this.mContext, titles, icons, Theme.getColor(Theme.key_windowBackgroundWhiteBlackText), new FcCommMenuDialog.RecyclerviewItemClickCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter.17
                    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcCommMenuDialog.RecyclerviewItemClickCallBack
                    public void onRecyclerviewItemClick(int index2) throws JSONException {
                        KLog.d(FcHomeAdapter.this.TAG, "onRecyclerviewItemClick operatePosition" + FcHomeAdapter.this.operatePosition);
                        if (isShowCancelFollow) {
                            if (index2 == 0) {
                                FcHomeAdapter.this.setAction(null, FcHomeAdapter.Index_click_pop_cancel_follow, FcHomeAdapter.this.operatePosition, FcHomeAdapter.this.operateModel);
                                return;
                            } else if (index2 == 1) {
                                FcHomeAdapter.this.setAction(null, FcHomeAdapter.Index_click_pop_shield_item, FcHomeAdapter.this.operatePosition, FcHomeAdapter.this.operateModel);
                                return;
                            } else {
                                if (index2 == 2) {
                                    FcHomeAdapter.this.setAction(null, FcHomeAdapter.Index_click_pop_report, FcHomeAdapter.this.operatePosition, FcHomeAdapter.this.operateModel);
                                    return;
                                }
                                return;
                            }
                        }
                        if (index2 == 0) {
                            FcHomeAdapter.this.setAction(null, FcHomeAdapter.Index_click_pop_shield_item, FcHomeAdapter.this.operatePosition, FcHomeAdapter.this.operateModel);
                        } else if (index2 == 1) {
                            FcHomeAdapter.this.setAction(null, FcHomeAdapter.Index_click_pop_report, FcHomeAdapter.this.operatePosition, FcHomeAdapter.this.operateModel);
                        }
                    }
                }, 1);
            }
            if (this.othersFcOperateDialog.isShowing()) {
                this.othersFcOperateDialog.dismiss();
            } else {
                this.othersFcOperateDialog.show();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setAction(View v, int index2, int position, Object o) {
        FcItemActionClickListener fcItemActionClickListener = this.listener;
        if (fcItemActionClickListener != null) {
            fcItemActionClickListener.onAction(v, index2, position, o);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onPresentDetailPage(RespFcListBean model) {
        FcItemActionClickListener fcItemActionClickListener;
        if (model != null && (fcItemActionClickListener = this.listener) != null) {
            fcItemActionClickListener.onPresentFragment(new FcPageDetailActivity(model, this.pageIndex, true));
        }
    }

    public void setHeaderCount(int mHeaderCount) {
        this.mHeaderCount = mHeaderCount;
    }

    public int getHeaderCount() {
        return this.mHeaderCount;
    }

    public int getHeaderFooterCount() {
        return this.mHeaderCount + this.mFooterCount;
    }

    public void setFooterCount(int mFooterCount) {
        this.mFooterCount = mFooterCount;
    }

    public void isShowReplyList(boolean isShowReply) {
        this.isShowReply = isShowReply;
    }

    public void isShowFollowBtn(boolean isShowFollow) {
        this.isShowFollow = isShowFollow;
    }

    public void removeItemByUserID(long userId) {
        if (this.mList != null && this.mList.size() > 0) {
            Iterator<RespFcListBean> iterator = this.mList.iterator();
            int i = 0;
            int startIndex = -1;
            int count = 0;
            while (iterator.hasNext()) {
                if (iterator.next().getCreateBy() == userId) {
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
