package im.uwrkaxlmjj.tgnet;

import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public class DOHBean {
    private boolean AD;
    private List<Answer> Answer;
    private boolean CD;
    private List<Question> Question;
    private boolean RA;
    private boolean RD;
    private int Status;
    private boolean TC;

    public void setStatus(int Status) {
        this.Status = Status;
    }

    public int getStatus() {
        return this.Status;
    }

    public void setTC(boolean TC) {
        this.TC = TC;
    }

    public boolean getTC() {
        return this.TC;
    }

    public void setRD(boolean RD) {
        this.RD = RD;
    }

    public boolean getRD() {
        return this.RD;
    }

    public void setRA(boolean RA) {
        this.RA = RA;
    }

    public boolean getRA() {
        return this.RA;
    }

    public void setAD(boolean AD) {
        this.AD = AD;
    }

    public boolean getAD() {
        return this.AD;
    }

    public void setCD(boolean CD) {
        this.CD = CD;
    }

    public boolean getCD() {
        return this.CD;
    }

    public void setQuestion(List<Question> Question2) {
        this.Question = Question2;
    }

    public List<Question> getQuestion() {
        return this.Question;
    }

    public void setAnswer(List<Answer> Answer2) {
        this.Answer = Answer2;
    }

    public List<Answer> getAnswer() {
        return this.Answer;
    }

    class Question {
        private String name;
        private int type;

        Question() {
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getName() {
            return this.name;
        }

        public void setType(int type) {
            this.type = type;
        }

        public int getType() {
            return this.type;
        }
    }

    class Answer {
        private String Expires;
        private int TTL;
        private String data;
        private String name;
        private int type;

        Answer() {
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getName() {
            return this.name;
        }

        public void setType(int type) {
            this.type = type;
        }

        public int getType() {
            return this.type;
        }

        public void setTTL(int TTL) {
            this.TTL = TTL;
        }

        public int getTTL() {
            return this.TTL;
        }

        public void setExpires(String Expires) {
            this.Expires = Expires;
        }

        public String getExpires() {
            return this.Expires;
        }

        public void setData(String data) {
            this.data = data;
        }

        public String getData() {
            return this.data;
        }
    }
}
