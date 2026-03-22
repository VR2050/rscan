package com.jbzd.media.movecartoons.bean.response;

import android.os.CountDownTimer;
import java.util.List;

/* loaded from: classes2.dex */
public class RechargeBean {
    private String balance;
    private String description;
    private String point_tips;
    private List<ProductsBean> products;
    private String tips;
    private String user_id;

    public static class ProductsBean {
        public String button_text;
        private CountDownTimer countDownTimer;
        public String gift_num;

        /* renamed from: id */
        public String f9984id;
        public String num;
        public List<PaymentsBean> payments;
        public String price;
        public String priceZero;
        public boolean isDiscount = false;
        public long expireAt = 0;
        public long duration = 0;

        public static class PaymentsBean {
            private boolean isChecked;
            private String payment_ico;
            private String payment_id;
            private String payment_name;
            private String type;

            public String getPayment_ico() {
                return this.payment_ico;
            }

            public String getPayment_id() {
                return this.payment_id;
            }

            public String getPayment_name() {
                return this.payment_name;
            }

            public String getType() {
                return this.type;
            }

            public boolean isChecked() {
                return this.isChecked;
            }

            public void setChecked(boolean z) {
                this.isChecked = z;
            }

            public void setPayment_ico(String str) {
                this.payment_ico = str;
            }

            public void setPayment_id(String str) {
                this.payment_id = str;
            }

            public void setPayment_name(String str) {
                this.payment_name = str;
            }

            public void setType(String str) {
                this.type = str;
            }
        }

        public String getGift_num() {
            return this.gift_num;
        }

        public String getId() {
            return this.f9984id;
        }

        public String getNum() {
            return this.num;
        }

        public List<PaymentsBean> getPayments() {
            return this.payments;
        }

        public String getPrice() {
            return this.price;
        }

        public String getPriceZero() {
            String replace = this.price.replace("元", ".00");
            this.priceZero = replace;
            return replace;
        }

        public boolean hasGift() {
            return !"0".equals(this.gift_num);
        }

        public void setGift_num(String str) {
            this.gift_num = str;
        }

        public void setId(String str) {
            this.f9984id = str;
        }

        public void setNum(String str) {
            this.num = str;
        }

        public void setPayments(List<PaymentsBean> list) {
            this.payments = list;
        }

        public void setPrice(String str) {
            this.price = str;
        }
    }

    public String getBalance() {
        return this.balance;
    }

    public String getDescription() {
        return this.description;
    }

    public String getPoint_tips() {
        return this.point_tips;
    }

    public List<ProductsBean> getProducts() {
        return this.products;
    }

    public String getTips() {
        return this.tips;
    }

    public String getUser_id() {
        return this.user_id;
    }

    public void setBalance(String str) {
        this.balance = str;
    }

    public void setDescription(String str) {
        this.description = str;
    }

    public void setPoint_tips(String str) {
        this.point_tips = str;
    }

    public void setProducts(List<ProductsBean> list) {
        this.products = list;
    }

    public void setTips(String str) {
        this.tips = str;
    }

    public void setUser_id(String str) {
        this.user_id = str;
    }
}
