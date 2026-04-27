package im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter;

import android.content.Context;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.style.ForegroundColorSpan;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RelativeLayout;
import androidx.core.content.ContextCompat;
import com.bjz.comm.net.bean.AvatarPhotoBean;
import com.bjz.comm.net.bean.FCEntitysResponse;
import com.bjz.comm.net.bean.FcReplyBean;
import com.bjz.comm.net.bean.FcUserInfoBean;
import com.bjz.comm.net.bean.TopicBean;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.hui.adapter.SmartViewHolder;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FCClickAtUserSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FCClickTopicSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FCLinkSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.StringUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.TimeUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcChildReplyListDialog;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanAtUserCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanCreateListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanTopicCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanUrlCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.ClickAtUserSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.ClickTopicSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.LinkSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextBuilder;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.Collection;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcDialogChildReplyAdapter extends BaseFcAdapter<FcReplyBean> {
    private static final int ITEM_TYPE_BOTTOM;
    private static final int ITEM_TYPE_HEADER = 0;
    private static final int ITEM_TYPE_REPLY;
    private static int itemType;
    private final int currentUserId;
    private FcChildReplyListDialog.ChildReplyListListener listener;
    private Context mContext;
    private final int mGuid;
    private FcReplyBean mParentFcReplyBean;
    private int mParentFcReplyPosition;
    private SpanCreateListener spanCreateListener;

    public FcDialogChildReplyAdapter(Collection<FcReplyBean> collection, Context mContext, int guid, FcChildReplyListDialog.ChildReplyListListener listener) {
        super(collection, R.layout.item_fc_detail_child_reply);
        this.spanCreateListener = new SpanCreateListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDialogChildReplyAdapter.9
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanCreateListener
            public ClickAtUserSpan getCustomClickAtUserSpan(Context context, FCEntitysResponse FCEntitysResponse, int color, SpanAtUserCallBack spanClickCallBack) {
                return new FCClickAtUserSpan(FcDialogChildReplyAdapter.this.mGuid, FCEntitysResponse, color, new SpanAtUserCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDialogChildReplyAdapter.9.1
                    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanAtUserCallBack
                    public void onPresentFragment(BaseFragment baseFragment) {
                        if (FcDialogChildReplyAdapter.this.listener != null && baseFragment != null) {
                            FcDialogChildReplyAdapter.this.listener.onPresentFragment(baseFragment);
                        }
                    }
                });
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanCreateListener
            public ClickTopicSpan getCustomClickTopicSpan(Context context, TopicBean topicBean, int color, SpanTopicCallBack spanTopicCallBack) {
                return new FCClickTopicSpan(topicBean, color, spanTopicCallBack);
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanCreateListener
            public LinkSpan getCustomLinkSpan(Context context, String url, int color, SpanUrlCallBack spanUrlCallBack) {
                return new FCLinkSpan(context, url, color, spanUrlCallBack);
            }
        };
        this.mContext = mContext;
        this.mGuid = guid;
        this.listener = listener;
        this.currentUserId = AccountInstance.getInstance(UserConfig.selectedAccount).getUserConfig().getCurrentUser().id;
    }

    public void setListener(FcChildReplyListDialog.ChildReplyListListener listener) {
        this.listener = listener;
    }

    public void setFcReplyBean(FcReplyBean ParentFcReplyBean, int ParentFcReplyPosition) {
        this.mParentFcReplyBean = ParentFcReplyBean;
        this.mParentFcReplyPosition = ParentFcReplyPosition;
    }

    public void setParentFcReplyBean(FcReplyBean mParentFcReplyBean) {
        this.mParentFcReplyBean = mParentFcReplyBean;
    }

    public void setParentFcReplyPosition(int mParentFcReplyPosition) {
        this.mParentFcReplyPosition = mParentFcReplyPosition;
    }

    public FcReplyBean getParentFcReplyBean() {
        return this.mParentFcReplyBean;
    }

    public int getParentFcReplyPosition() {
        return this.mParentFcReplyPosition;
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
        return ((FcReplyBean) this.mList.get((this.mList.size() - 1) - getFooterSize())).getCommentID();
    }

    public int getFooterSize() {
        FcReplyBean fcReplyBean;
        return (getDataList().size() <= 1 || (fcReplyBean = getDataList().get(getItemCount() - 1)) == null || fcReplyBean.getCommentID() != 0) ? 0 : 1;
    }

    static {
        itemType = 0;
        int i = 0 + 1;
        itemType = i;
        int i2 = i + 1;
        itemType = i2;
        ITEM_TYPE_BOTTOM = i;
        itemType = i2 + 1;
        ITEM_TYPE_REPLY = i2;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int position) {
        if (position == 0 && this.mParentFcReplyBean != null) {
            return ITEM_TYPE_HEADER;
        }
        if (position == getItemCount() - 1 && ((FcReplyBean) this.mList.get(position)).getCommentID() == 0) {
            return ITEM_TYPE_BOTTOM;
        }
        return ITEM_TYPE_REPLY;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public SmartViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        if (viewType == ITEM_TYPE_HEADER) {
            return new SmartViewHolder(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_fc_reply_list_header, parent, false), this.mListener);
        }
        if (viewType == ITEM_TYPE_BOTTOM) {
            return new SmartViewHolder(LayoutInflater.from(parent.getContext()).inflate(R.layout.view_fc_footer, parent, false), this.mListener);
        }
        return new SmartViewHolder(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_fc_detail_child_reply, parent, false), this.mListener);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter
    public void onBindViewHolder(SmartViewHolder viewHolder, final FcReplyBean model, final int position) {
        viewHolder.itemView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        if (getItemViewType(position) != ITEM_TYPE_HEADER) {
            if (getItemViewType(position) != ITEM_TYPE_BOTTOM) {
                View itemView = viewHolder.itemView;
                RichTextView txt_parent_comment = (RichTextView) itemView.findViewById(R.attr.txt_parent_comment);
                BackupImageView ivUserAvatar = (BackupImageView) itemView.findViewById(R.attr.iv_user_avatar);
                ivUserAvatar.setRoundRadius(AndroidUtilities.dp(5.0f));
                MryTextView tvUserName = (MryTextView) itemView.findViewById(R.attr.tv_user_name);
                MryTextView tvPublishTime = (MryTextView) itemView.findViewById(R.attr.tv_publish_time);
                final MryTextView btnLike = (MryTextView) itemView.findViewById(R.attr.btn_like);
                itemView.findViewById(R.attr.view_divider).setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
                bindUserInfo(model.getCreator(), model.getCreateAt(), ivUserAvatar, tvUserName, tvPublishTime, position);
                btnLike.setSelected(model.isHasThumb());
                btnLike.setText(model.getThumbUp() > 0 ? String.valueOf(model.getThumbUp()) : "0");
                btnLike.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDialogChildReplyAdapter.2
                    @Override // android.view.View.OnClickListener
                    public void onClick(View v) {
                        btnLike.setClickable(false);
                        FcDialogChildReplyAdapter.this.setAction(v, FcDetailAdapter.Index_child_reply_click_like, position, model);
                    }
                });
                bindReplyView(model, txt_parent_comment, true, position, itemView);
            }
        } else {
            View itemView2 = viewHolder.itemView;
            BackupImageView ivUserAvatar2 = (BackupImageView) itemView2.findViewById(R.attr.iv_user_avatar);
            ivUserAvatar2.setRoundRadius(AndroidUtilities.dp(5.0f));
            MryTextView tvUserName2 = (MryTextView) itemView2.findViewById(R.attr.tv_user_name);
            MryTextView tvPublishTime2 = (MryTextView) itemView2.findViewById(R.attr.tv_publish_time);
            final MryTextView btnLike2 = (MryTextView) itemView2.findViewById(R.attr.btn_like);
            RichTextView txt_parent_comment2 = (RichTextView) itemView2.findViewById(R.attr.txt_parent_comment);
            itemView2.findViewById(R.attr.view_divider).setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
            bindUserInfo(this.mParentFcReplyBean.getCreator(), this.mParentFcReplyBean.getCreateAt(), ivUserAvatar2, tvUserName2, tvPublishTime2, position);
            btnLike2.setSelected(this.mParentFcReplyBean.isHasThumb());
            btnLike2.setText(this.mParentFcReplyBean.getThumbUp() > 0 ? String.valueOf(this.mParentFcReplyBean.getThumbUp()) : "0");
            btnLike2.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDialogChildReplyAdapter.1
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    btnLike2.setClickable(false);
                    FcDialogChildReplyAdapter.this.setAction(v, FcDetailAdapter.Index_child_reply_click_like, position, FcDialogChildReplyAdapter.this.mParentFcReplyBean);
                }
            });
            bindReplyView(this.mParentFcReplyBean, txt_parent_comment2, false, position, itemView2);
        }
    }

    private RichTextView bindReplyView(final FcReplyBean model, RichTextView txt_comment, boolean isReply, final int position, View itemView) {
        RichTextView txt_comment2;
        if (txt_comment != null) {
            txt_comment2 = txt_comment;
        } else {
            txt_comment2 = new RichTextView(this.mContext);
            txt_comment2.setLayoutParams(new RelativeLayout.LayoutParams(-1, -2));
        }
        RichTextBuilder richTextBuilder = new RichTextBuilder(this.mContext);
        richTextBuilder.setContent(model.getContent() == null ? "" : model.getContent()).setLinkColor(ContextCompat.getColor(this.mContext, R.color.color_FF09A4C9)).setAtColor(ContextCompat.getColor(this.mContext, R.color.color_FF09A4C9)).setTextView(txt_comment2).setListUser(model.getEntitys()).setNeedUrl(true).setSpanCreateListener(this.spanCreateListener).build();
        FcUserInfoBean replayUserInfo = model.getReplayUser();
        if (isReply && replayUserInfo != null) {
            SpannableStringBuilder headerStr = new SpannableStringBuilder();
            if (model.getReplayID() != this.mParentFcReplyBean.getForumID()) {
                String reply = LocaleController.getString("Reply", R.string.Reply);
                headerStr.append((CharSequence) reply);
                headerStr.setSpan(new ForegroundColorSpan(this.mContext.getResources().getColor(R.color.color_FF2ECEFD)), 0, headerStr.length(), 33);
                int StartIndex = headerStr.length();
                String replyUserName = StringUtils.handleTextName(ContactsController.formatName(replayUserInfo.getFirstName(), replayUserInfo.getLastName()), 12);
                headerStr.append((CharSequence) replyUserName);
                headerStr.append((CharSequence) " : ");
                headerStr.setSpan(new ForegroundColorSpan(this.mContext.getResources().getColor(R.color.color_FF2ECEFD)), StartIndex, headerStr.length(), 33);
            }
            CharSequence content = txt_comment2.getText();
            if (!TextUtils.isEmpty(headerStr) && !TextUtils.isEmpty(content)) {
                SpannableStringBuilder stringBuilder = new SpannableStringBuilder(content);
                stringBuilder.insert(0, (CharSequence) headerStr, 0, headerStr.length());
                txt_comment2.setText(stringBuilder);
            }
            FcUserInfoBean creatorUserInfo = model.getCreator();
            String receiver = "";
            if (creatorUserInfo != null) {
                receiver = StringUtils.handleTextName(ContactsController.formatName(creatorUserInfo.getFirstName(), creatorUserInfo.getLastName()), 12);
            }
            final String finalCommentUserName = receiver;
            if (itemView != null) {
                itemView.setOnLongClickListener(new View.OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDialogChildReplyAdapter.3
                    @Override // android.view.View.OnLongClickListener
                    public boolean onLongClick(View v) {
                        if (FcDialogChildReplyAdapter.this.listener != null) {
                            FcDialogChildReplyAdapter.this.listener.onChildReplyClick(v, finalCommentUserName, model, FcDialogChildReplyAdapter.this.mParentFcReplyPosition, position, true);
                            return true;
                        }
                        return true;
                    }
                });
                int i = this.currentUserId;
                if (i != 0 && i != model.getCreateBy()) {
                    itemView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDialogChildReplyAdapter.4
                        @Override // android.view.View.OnClickListener
                        public void onClick(View v) {
                            if (FcDialogChildReplyAdapter.this.listener != null) {
                                FcDialogChildReplyAdapter.this.listener.onChildReplyClick(v, finalCommentUserName, model, FcDialogChildReplyAdapter.this.mParentFcReplyPosition, position, false);
                            }
                        }
                    });
                }
            }
            txt_comment2.setOnLongClickListener(new View.OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDialogChildReplyAdapter.5
                @Override // android.view.View.OnLongClickListener
                public boolean onLongClick(View v) {
                    if (FcDialogChildReplyAdapter.this.listener != null) {
                        FcDialogChildReplyAdapter.this.listener.onChildReplyClick(v, finalCommentUserName, model, FcDialogChildReplyAdapter.this.mParentFcReplyPosition, position, true);
                        return true;
                    }
                    return true;
                }
            });
            int i2 = this.currentUserId;
            if (i2 != 0 && i2 != model.getCreateBy()) {
                txt_comment2.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDialogChildReplyAdapter.6
                    @Override // android.view.View.OnClickListener
                    public void onClick(View v) {
                        if (FcDialogChildReplyAdapter.this.listener != null) {
                            FcDialogChildReplyAdapter.this.listener.onChildReplyClick(v, finalCommentUserName, model, FcDialogChildReplyAdapter.this.mParentFcReplyPosition, position, false);
                        }
                    }
                });
            }
        }
        return txt_comment2;
    }

    private void bindUserInfo(FcUserInfoBean fcUserInfoBean, long createAt, BackupImageView ivUserAvatar, MryTextView tvUserName, MryTextView tvPublishTime, final int position) {
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
                    ivUserAvatar.setImage(imageLocation, "40_40", drawable, inputPeer);
                }
            }
            tvUserName.setText(StringUtils.handleTextName(ContactsController.formatName(fcUserInfoBean.getFirstName(), fcUserInfoBean.getLastName()), 12));
            tvPublishTime.setText(TimeUtils.fcFormat2Date(createAt));
            ivUserAvatar.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDialogChildReplyAdapter.7
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    FcDialogChildReplyAdapter.this.setAction(v, FcDetailAdapter.Index_child_reply_click_avatar, position, FcDialogChildReplyAdapter.this.mParentFcReplyBean);
                }
            });
            tvUserName.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDialogChildReplyAdapter.8
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    FcDialogChildReplyAdapter.this.setAction(v, FcDetailAdapter.Index_child_reply_click_avatar, position, FcDialogChildReplyAdapter.this.mParentFcReplyBean);
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setAction(View v, int index, int position, Object o) {
        FcChildReplyListDialog.ChildReplyListListener childReplyListListener = this.listener;
        if (childReplyListListener != null) {
            childReplyListListener.onChildReplyListAction(v, index, position, o);
        }
    }
}
