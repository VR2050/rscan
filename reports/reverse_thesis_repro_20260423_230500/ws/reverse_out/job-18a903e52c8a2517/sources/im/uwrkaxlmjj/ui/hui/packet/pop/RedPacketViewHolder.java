package im.uwrkaxlmjj.ui.hui.packet.pop;

import android.content.Context;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import butterknife.ButterKnife;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.hui.packet.bean.RedpacketBean;
import im.uwrkaxlmjj.ui.hui.packet.bean.RedpacketResponse;
import im.uwrkaxlmjj.ui.hui.packet.pop.FrameAnimation;
import im.uwrkaxlmjj.ui.utils.number.TimeUtils;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class RedPacketViewHolder implements View.OnClickListener {
    private Context mContext;
    private FrameAnimation mFrameAnimation;
    private int[] mImgResIds = {R.id.icon_open_red_packet1, R.id.icon_open_red_packet2, R.id.icon_open_red_packet3, R.id.icon_open_red_packet4, R.id.icon_open_red_packet5, R.id.icon_open_red_packet6, R.id.icon_open_red_packet7, R.id.icon_open_red_packet7, R.id.icon_open_red_packet8, R.id.icon_open_red_packet9, R.id.icon_open_red_packet4, R.id.icon_open_red_packet10, R.id.icon_open_red_packet11};
    private BackupImageView mIvAvatar;
    private ImageView mIvClose;
    private ImageView mIvOpen;
    private OnRedPacketDialogClickListener mListener;
    private TextView mTvDetail;
    private TextView mTvMsg;
    private TextView mTvName;
    private RedpacketResponse ret;

    public RedPacketViewHolder(Context context, View view) {
        this.mContext = context;
        ButterKnife.bind(this, view);
        this.mIvClose = (ImageView) view.findViewById(R.attr.iv_close);
        this.mIvAvatar = (BackupImageView) view.findViewById(R.attr.iv_avatar);
        this.mTvName = (TextView) view.findViewById(R.attr.tv_name);
        this.mTvMsg = (TextView) view.findViewById(R.attr.tv_msg);
        this.mIvOpen = (ImageView) view.findViewById(R.attr.iv_open);
        this.mTvDetail = (TextView) view.findViewById(R.attr.tv_details);
        this.mTvMsg.setSelected(true);
        this.mIvOpen.setOnClickListener(this);
        this.mIvClose.setOnClickListener(this);
        this.mTvDetail.setOnClickListener(this);
    }

    public void setPromtText(final String text, final boolean showDetail) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.pop.RedPacketViewHolder.1
            @Override // java.lang.Runnable
            public void run() {
                RedPacketViewHolder.this.mTvMsg.setText(text);
                RedPacketViewHolder.this.stopAnim();
                RedPacketViewHolder.this.mIvOpen.setVisibility(8);
                if (showDetail) {
                    RedPacketViewHolder.this.mTvDetail.setVisibility(0);
                }
            }
        });
    }

    public void setPromtText(String text) {
        setPromtText(text, false);
    }

    public void setRet(RedpacketResponse ret) {
        this.ret = ret;
    }

    public void clear() {
        this.ret = null;
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        OnRedPacketDialogClickListener onRedPacketDialogClickListener;
        int id = view.getId();
        if (id == R.attr.iv_close) {
            stopAnim();
            OnRedPacketDialogClickListener onRedPacketDialogClickListener2 = this.mListener;
            if (onRedPacketDialogClickListener2 != null) {
                onRedPacketDialogClickListener2.onCloseClick();
                return;
            }
            return;
        }
        if (id != R.attr.iv_open) {
            if (id == R.attr.tv_details && (onRedPacketDialogClickListener = this.mListener) != null) {
                onRedPacketDialogClickListener.toDetail(this.ret);
                return;
            }
            return;
        }
        if (this.mFrameAnimation != null) {
            return;
        }
        startAnim();
        OnRedPacketDialogClickListener onRedPacketDialogClickListener3 = this.mListener;
        if (onRedPacketDialogClickListener3 != null) {
            onRedPacketDialogClickListener3.onOpenClick();
        }
    }

    public void setData(TLRPC.User sender, RedpacketResponse bean, boolean isChat) {
        if (bean != null && bean.getRed() != null) {
            RedpacketBean red = bean.getRed();
            if ("2".equals(red.getRedType())) {
                String userId = red.getRecipientUserId();
                boolean exclusive = UserConfig.getInstance(UserConfig.selectedAccount).clientUserId == Integer.parseInt(userId);
                TLRPC.User user = MessagesController.getInstance(UserConfig.selectedAccount).getUser(Integer.valueOf(Integer.parseInt(userId)));
                AvatarDrawable avatarDrawable = new AvatarDrawable();
                avatarDrawable.setTextSize(AndroidUtilities.dp(16.0f));
                avatarDrawable.setInfo(user);
                this.mIvAvatar.setRoundRadius(AndroidUtilities.dp(7.0f));
                this.mIvAvatar.setImage(ImageLocation.getForUser(user, false), "50_50", avatarDrawable, user);
                this.mTvName.setText(UserObject.getName(user, 6) + LocaleController.getString(R.string.redpacket_group_exclusive));
                this.mTvName.setTextColor(-338532);
                if (exclusive) {
                    int status = Integer.parseInt(red.getStatus());
                    this.mTvMsg.setTextColor(-1);
                    if (status == 2) {
                        this.mTvMsg.setText(String.format("" + LocaleController.getString(R.string.ThisRedPacketsAlreadyBy) + "%s" + LocaleController.getString(R.string.Overdue), TimeUtils.getTimeString(Long.parseLong(red.getCreateTime()) + 86400000, LocaleController.getString(R.string.formatterMonthDayTime24H2))));
                        this.mIvOpen.setVisibility(8);
                    } else {
                        this.mIvOpen.setVisibility(0);
                        if (bean.getRed().getRemarks() != null && !TextUtils.isEmpty(bean.getRed().getRemarks())) {
                            this.mTvMsg.setText(bean.getRed().getRemarks());
                            this.mTvMsg.setTextColor(-1);
                        } else {
                            this.mTvMsg.setText(LocaleController.getString(R.string.redpacket_greetings_tip));
                            this.mTvMsg.setTextColor(-1);
                        }
                    }
                    this.mTvDetail.setVisibility(0);
                    this.mTvDetail.setText(LocaleController.getString(R.string.From) + sender.first_name);
                    this.mTvDetail.setTextColor(-338532);
                    return;
                }
                this.mIvOpen.setVisibility(8);
                this.mTvMsg.setText(LocaleController.getString(R.string.ExclusiveRedBagCannotGetIt));
                this.mTvMsg.setTextColor(-1);
                this.mTvDetail.setVisibility(0);
                this.mTvDetail.setText(LocaleController.getString(R.string.CheckHotCoinCount));
                this.mTvDetail.setTextColor(-338532);
                return;
            }
            if (sender != null) {
                AvatarDrawable avatarDrawable2 = new AvatarDrawable();
                avatarDrawable2.setTextSize(AndroidUtilities.dp(16.0f));
                avatarDrawable2.setInfo(sender);
                this.mIvAvatar.setRoundRadius(AndroidUtilities.dp(7.0f));
                this.mIvAvatar.setImage(ImageLocation.getForUser(sender, false), "50_50", avatarDrawable2, sender);
                if (isChat) {
                    StringBuilder builder = new StringBuilder(sender.first_name);
                    int redType = bean.getRed().getRedTypeInt();
                    if (redType != 0) {
                        if (redType == 1) {
                            int grantType = bean.getRed().getGrantTypeInt();
                            if (grantType == 0) {
                                builder.append(LocaleController.getString(R.string.SentANormalRedPackets));
                            } else {
                                builder.append(LocaleController.getString(R.string.SentALuckRedPackets));
                            }
                        } else if (redType == 2) {
                            builder.append(LocaleController.getString(R.string.SentALuckRExclusivePackets));
                        }
                    }
                    this.mTvName.setText(builder.toString());
                    this.mTvName.setTextColor(-338532);
                } else {
                    this.mTvName.setText(sender.first_name + LocaleController.getString(R.string.SentARedPacketsToYou));
                    this.mTvName.setTextColor(-338532);
                }
            }
            int status2 = Integer.parseInt(red.getStatus());
            if (status2 == 2) {
                this.mTvMsg.setText(String.format(LocaleController.getString(R.string.ThisRedPacketsAlreadyBy) + "%s" + LocaleController.getString(R.string.Overdue), TimeUtils.getTimeString(Long.parseLong(red.getCreateTime()) + 86400000, LocaleController.getString(R.string.formatterMonthDayTime24H2))));
                this.mTvMsg.setTextColor(-1);
                this.mIvOpen.setVisibility(8);
                this.mTvDetail.setVisibility(isChat ? 0 : 8);
                this.mTvDetail.setText(LocaleController.getString(R.string.LookReceivedDetails) + " >");
                this.mTvDetail.setTextColor(-338532);
                this.mTvDetail.setEnabled(true);
                return;
            }
            if (status2 == 1) {
                this.mTvMsg.setText(LocaleController.getString(R.string.ToLateRedPacketsIsAllHadBeenReceived));
                this.mTvMsg.setTextColor(-1);
                this.mIvOpen.setVisibility(8);
                this.mTvDetail.setVisibility(0);
                this.mTvDetail.setText(LocaleController.getString(R.string.LookReceivedDetails) + " >");
                this.mTvDetail.setTextColor(-338532);
                this.mTvDetail.setEnabled(true);
                return;
            }
            this.mIvOpen.setVisibility(0);
            this.mTvDetail.setText(LocaleController.getString(R.string.LookReceivedDetails) + " >");
            if (isChat) {
                if (red.getIsReceived() == 0 && sender != null && sender.id != UserConfig.getInstance(UserConfig.selectedAccount).clientUserId) {
                    this.mTvDetail.setVisibility(8);
                } else {
                    this.mTvDetail.setVisibility(0);
                }
            } else {
                this.mTvDetail.setVisibility(8);
            }
            this.mTvDetail.setEnabled(true);
            this.mTvDetail.setTextColor(-338532);
            if (bean.getRed().getRemarks() != null && !TextUtils.isEmpty(bean.getRed().getRemarks())) {
                this.mTvMsg.setText(bean.getRed().getRemarks());
                this.mTvMsg.setTextColor(-1);
            } else {
                this.mTvMsg.setText(LocaleController.getString(R.string.redpacket_greetings_tip));
                this.mTvMsg.setTextColor(-1);
            }
        }
    }

    public void startAnim() {
        FrameAnimation frameAnimation = new FrameAnimation(this.mIvOpen, this.mImgResIds, 125, true);
        this.mFrameAnimation = frameAnimation;
        frameAnimation.setAnimationListener(new FrameAnimation.AnimationListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.pop.RedPacketViewHolder.2
            @Override // im.uwrkaxlmjj.ui.hui.packet.pop.FrameAnimation.AnimationListener
            public void onAnimationStart() {
                Log.i("", TtmlNode.START);
            }

            @Override // im.uwrkaxlmjj.ui.hui.packet.pop.FrameAnimation.AnimationListener
            public void onAnimationEnd() {
                Log.i("", TtmlNode.END);
            }

            @Override // im.uwrkaxlmjj.ui.hui.packet.pop.FrameAnimation.AnimationListener
            public void onAnimationRepeat() {
                Log.i("", "repeat");
            }

            @Override // im.uwrkaxlmjj.ui.hui.packet.pop.FrameAnimation.AnimationListener
            public void onAnimationPause() {
                RedPacketViewHolder.this.mIvOpen.setBackgroundResource(R.id.icon_open_red_packet1);
            }
        });
    }

    public void stopAnim() {
        FrameAnimation frameAnimation = this.mFrameAnimation;
        if (frameAnimation != null) {
            frameAnimation.release();
            this.mFrameAnimation = null;
        }
    }

    public void setOnRedPacketDialogClickListener(OnRedPacketDialogClickListener listener) {
        this.mListener = listener;
    }
}
