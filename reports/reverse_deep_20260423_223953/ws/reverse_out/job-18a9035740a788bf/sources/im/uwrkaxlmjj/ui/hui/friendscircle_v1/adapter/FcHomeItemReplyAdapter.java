package im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter;

import android.content.Context;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.style.ForegroundColorSpan;
import android.view.View;
import androidx.core.content.ContextCompat;
import com.bjz.comm.net.bean.FCEntitysResponse;
import com.bjz.comm.net.bean.FcReplyBean;
import com.bjz.comm.net.bean.FcUserInfoBean;
import com.bjz.comm.net.bean.RespFcListBean;
import com.bjz.comm.net.bean.TopicBean;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.hui.adapter.SmartViewHolder;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FCClickAtUserSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FCClickTopicSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FCLinkSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.StringUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanAtUserCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanCreateListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanTopicCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanUrlCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.ClickAtUserSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.ClickTopicSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.LinkSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextBuilder;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextView;
import java.util.Collection;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcHomeItemReplyAdapter extends BaseFcAdapter<FcReplyBean> {
    private final int currentUserId;
    private final boolean isThemeLight;
    private int itemPosition;
    private final FcItemActionClickListener listener;
    private Context mContext;
    private final int mGuid;
    private RespFcListBean model;
    private int page;
    private SpanCreateListener spanCreateListener;

    public FcHomeItemReplyAdapter(Context context, Collection<FcReplyBean> collection, int layoutId, boolean flag, int itemPosition, RespFcListBean model, int page, int mGuid, FcItemActionClickListener listener) {
        super(collection, layoutId);
        this.page = 0;
        this.spanCreateListener = new SpanCreateListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeItemReplyAdapter.3
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanCreateListener
            public ClickAtUserSpan getCustomClickAtUserSpan(Context context2, FCEntitysResponse FCEntitysResponse, int color, SpanAtUserCallBack spanClickCallBack) {
                return new FCClickAtUserSpan(FcHomeItemReplyAdapter.this.mGuid, FCEntitysResponse, color, new SpanAtUserCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeItemReplyAdapter.3.1
                    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanAtUserCallBack
                    public void onPresentFragment(BaseFragment baseFragment) {
                        if (FcHomeItemReplyAdapter.this.listener != null && baseFragment != null) {
                            FcHomeItemReplyAdapter.this.listener.onPresentFragment(baseFragment);
                        }
                    }
                });
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanCreateListener
            public ClickTopicSpan getCustomClickTopicSpan(Context context2, TopicBean topicBean, int color, SpanTopicCallBack spanTopicCallBack) {
                return new FCClickTopicSpan(topicBean, color, spanTopicCallBack);
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanCreateListener
            public LinkSpan getCustomLinkSpan(Context context2, String url, int color, SpanUrlCallBack spanUrlCallBack) {
                return new FCLinkSpan(context2, url, color, spanUrlCallBack);
            }
        };
        this.mContext = context;
        this.flag = flag;
        this.itemPosition = itemPosition;
        this.model = model;
        this.page = page;
        this.listener = listener;
        this.mGuid = mGuid;
        this.currentUserId = AccountInstance.getInstance(UserConfig.selectedAccount).getUserConfig().getCurrentUser().id;
        this.isThemeLight = Theme.getCurrentTheme().isLight();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter
    public void onBindViewHolder(SmartViewHolder abrItem, FcReplyBean model, final int position) {
        abrItem.itemView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        RichTextView txt_comment = (RichTextView) abrItem.itemView.findViewById(R.attr.txt_comment);
        if (this.isThemeLight) {
            txt_comment.setTextColor(this.mContext.getResources().getColor(R.color.color_FF838383));
        } else {
            txt_comment.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
        }
        int commenterColor = this.isThemeLight ? this.mContext.getResources().getColor(R.color.color_FF313131) : Theme.getColor(Theme.key_windowBackgroundWhiteBlackText);
        int replyUserColor = this.isThemeLight ? this.mContext.getResources().getColor(R.color.color_FF838383) : Theme.getColor(Theme.key_windowBackgroundWhiteGrayText);
        RichTextBuilder richTextBuilder = new RichTextBuilder(this.mContext);
        richTextBuilder.setContent(model.getContent() == null ? "" : model.getContent()).setLinkColor(ContextCompat.getColor(this.mContext, R.color.color_FF09A4C9)).setAtColor(ContextCompat.getColor(this.mContext, R.color.color_FF09A4C9)).setTextView(txt_comment).setListUser(this.page == 3 ? model.getEntitys() : null).setNeedUrl(true).setSpanCreateListener(this.spanCreateListener).build();
        FcUserInfoBean creator = model.getCreator();
        if (creator != null) {
            final String commentUserName = StringUtils.handleTextName(ContactsController.formatName(creator.getFirstName(), creator.getLastName()), 12);
            SpannableStringBuilder headerStr = new SpannableStringBuilder();
            if (model.getReplayID() == model.getForumID()) {
                headerStr.append((CharSequence) commentUserName);
                headerStr.append((CharSequence) " : ");
                headerStr.setSpan(new ForegroundColorSpan(commenterColor), 0, headerStr.length(), 33);
            } else {
                headerStr.append((CharSequence) commentUserName);
                headerStr.setSpan(new ForegroundColorSpan(commenterColor), 0, commentUserName.length(), 34);
                headerStr.append((CharSequence) " ");
                String reply = LocaleController.getString("Reply", R.string.Reply);
                headerStr.append((CharSequence) reply);
                headerStr.append((CharSequence) " ");
                headerStr.setSpan(new ForegroundColorSpan(this.mContext.getResources().getColor(R.color.color_FF2ECEFD)), commentUserName.length(), headerStr.length(), 33);
                int StartIndex = headerStr.length();
                FcUserInfoBean replayUser = model.getReplayUser();
                String replyUserName = StringUtils.handleTextName(ContactsController.formatName(replayUser.getFirstName(), replayUser.getLastName()), 12);
                headerStr.append((CharSequence) replyUserName);
                headerStr.setSpan(new ForegroundColorSpan(replyUserColor), StartIndex, headerStr.length(), 33);
                headerStr.append((CharSequence) " : ");
            }
            CharSequence content = txt_comment.getText();
            if (!TextUtils.isEmpty(headerStr) && !TextUtils.isEmpty(content)) {
                SpannableStringBuilder stringBuilder = new SpannableStringBuilder(content);
                stringBuilder.insert(0, (CharSequence) headerStr, 0, headerStr.length());
                txt_comment.setText(stringBuilder);
            }
            txt_comment.setOnLongClickListener(new View.OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeItemReplyAdapter.1
                @Override // android.view.View.OnLongClickListener
                public boolean onLongClick(View v) {
                    FcHomeItemReplyAdapter.this.listener.onReplyClick(v, commentUserName, FcHomeItemReplyAdapter.this.model, FcHomeItemReplyAdapter.this.itemPosition, position, true);
                    return true;
                }
            });
            int i = this.currentUserId;
            if (i != 0 && i != model.getCreateBy()) {
                txt_comment.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeItemReplyAdapter.2
                    @Override // android.view.View.OnClickListener
                    public void onClick(View v) {
                        if (FcHomeItemReplyAdapter.this.listener != null) {
                            FcHomeItemReplyAdapter.this.listener.onReplyClick(v, commentUserName, FcHomeItemReplyAdapter.this.model, FcHomeItemReplyAdapter.this.itemPosition, position, false);
                        }
                    }
                });
            }
        }
    }
}
