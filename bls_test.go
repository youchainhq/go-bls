package go_bls

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
	"time"
)

var blsMgr = NewBlsManager()

func TestBlsMgr_GenerateKey(t *testing.T) {
	sk, pk := blsMgr.GenerateKey()
	assert.NotEmpty(t, sk, "gen key fail")
	assert.NotEmpty(t, pk, "gen key fail")
	pk1, err := sk.PubKey()
	assert.NoError(t, err, "expect no error")
	bpk := pk.Compress()
	bpk1 := pk1.Compress()
	assert.EqualValues(t, bpk, bpk1, "public key not equal", bpk, bpk1)
	//t.Log(bpk)
	//t.Log(bpk1)

	sk2, _ := blsMgr.GenerateKey()
	bsk, bsk2 := sk.Compress(), sk2.Compress()
	assert.NotEqual(t, bsk, bsk2, "should not generate two same key", bsk, bsk2)
	//t.Log(bsk)
	//t.Log(bsk2)
}

func TestSingleSignAndVerify(t *testing.T) {
	sk, pk := blsMgr.GenerateKey()
	m1 := Message("message to be signed. 将要做签名的消息")
	//pair sign and verify
	sig1 := sk.Sign(m1)
	err := pk.Verify(m1, sig1)
	assert.NoError(t, err)

	//different message should have different signature
	m2 := Message("message to be signed. 将要做签名的消息.")
	sig2 := sk.Sign(m2)
	assert.NotEqual(t, sig1, sig2, "different message got the same signature", sig1, sig2)

	//different key should have different signature for a same message.
	sk2, _ := blsMgr.GenerateKey()
	sig12 := sk2.Sign(m1)
	err = pk.Verify(m1, sig12)
	assert.Error(t, err)
}

//contains test case of Compress and Decompress both for secret key and public key
func TestBlsManager_Decompress(t *testing.T) {
	sk, pk := blsMgr.GenerateKey()
	bsk, bpk := sk.Compress(), pk.Compress()
	dsk, err := blsMgr.DecompressPrivateKey(bsk)
	assert.NoError(t, err)
	dpk, err := blsMgr.DecompressPublicKey(bpk)
	assert.NoError(t, err)

	//cross sign and verify
	m1 := Message("message to be signed. 将要做签名的消息")
	sig1 := sk.Sign(m1)
	err = dpk.Verify(m1, sig1)
	assert.NoError(t, err)
	sig2 := dsk.Sign(m1)
	assert.EqualValues(t, sig1, sig2)
}

func TestBlsManager_Aggregate(t *testing.T) {
	m := Message("message to be signed. 将要做签名的消息")
	n := 8
	//sks := make([]SecretKey, 0, n)
	pubs := make([]PublicKey, 0, n)
	sigs := make([]Signature, 0, n) //signatures for the same message
	msgs := make([]Message, 0, n)
	dsigs := make([]Signature, 0, n) //signatures for each (key,message) pair
	for i := 0; i < n; i++ {
		sk, pk := blsMgr.GenerateKey()
		//sks = append(sks, sk)
		pubs = append(pubs, pk)
		sigs = append(sigs, sk.Sign(m))

		msgi := append(m, byte(i))
		msgs = append(msgs, msgi)
		dsigs = append(dsigs, sk.Sign(msgi))
	}

	asig, err := blsMgr.Aggregate(sigs)
	assert.NoError(t, err)
	// One
	err = blsMgr.VerifyAggregatedOne(pubs, m, asig)
	assert.NoError(t, err)

	apub, err := blsMgr.AggregatePublic(pubs)
	assert.NoError(t, err)

	err = apub.Verify(m, asig)
	assert.NoError(t, err)

	// N
	adsig, err := blsMgr.Aggregate(dsigs)
	assert.NoError(t, err)

	err = blsMgr.VerifyAggregatedN(pubs, msgs, adsig)
	assert.NoError(t, err)

	//lose some messages will cause an error
	err = blsMgr.VerifyAggregatedN(pubs, msgs[1:], adsig)
	assert.Error(t, err)

	//with out-of-order public keys, will has no effect on VerifyAggregatedOne, but DO effects VerifyAggregatedN
	pubs[0], pubs[1] = pubs[1], pubs[0]
	err = blsMgr.VerifyAggregatedOne(pubs, m, asig)
	assert.NoError(t, err)

	err = blsMgr.VerifyAggregatedN(pubs, msgs, adsig)
	assert.Error(t, err)

}

func TestRogueKey(t *testing.T) {
	var rcp CompressedPublic
	rand.Seed(time.Now().Unix())
	rand.Read(rcp[:])

	_, err := blsMgr.DecompressPublicKey(rcp)
	assert.Error(t, err)
	t.Log(err)
}

//benchmark

func BenchmarkBLSAggregateSignature(b *testing.B) {
	msg := Message(">16 character identical message")
	n := 2
	sigs := make([]Signature, 0, n) //signatures for the same message
	for i := 0; i < n; i++ {
		sk, _ := blsMgr.GenerateKey()
		sigs = append(sigs, sk.Sign(msg))

	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blsMgr.Aggregate(sigs) //nolint:errcheck
	}
}

func BenchmarkBLSSign(b *testing.B) {
	sks := make([]SecretKey, b.N)
	for i := range sks {
		sks[i], _ = blsMgr.GenerateKey()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {

		msg := Message(fmt.Sprintf("Hello world! 16 characters %d", i))
		sks[i].Sign(msg)
	}
}

func BenchmarkBLSVerify(b *testing.B) {
	sk, pk := blsMgr.GenerateKey()
	m := Message(">16 character identical message")
	sig := sk.Sign(m)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(m, sig) //nolint:errcheck
	}
}

func BenchmarkBlsDecompressPublicKey(b *testing.B) {
	_, pk := blsMgr.GenerateKey()
	cpk := pk.Compress()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blsMgr.DecompressPublicKey(cpk) //nolint:errcheck
	}
}
