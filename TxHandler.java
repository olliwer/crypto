import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

public class TxHandler {

    private UTXOPool utxoPool;
    
    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
    	List<UTXO> unclaimed = new ArrayList<UTXO>();
    	
    	double outputValues = 0;
    	double inputValues = 0;
    	
    	for (int i = 0; i < tx.numOutputs(); i++) {
    		Transaction.Output output = tx.getOutput(i);
    		
    		if (output == null || output.value < 0) {
    			return false;
    		}
    		
    		outputValues += output.value;
    	}
    	
    	for (int i = 0; i < tx.numInputs(); i++){
    		Transaction.Input input = tx.getInput(i);
    		if (input == null) {
    			return false;
    		}
    		
    		UTXO u = new UTXO(input.prevTxHash, input.outputIndex);
    		if (!this.utxoPool.contains(u) || unclaimed.contains(u)){
    			return false;
    		}
    		
    		Transaction.Output out = this.utxoPool.getTxOutput(u);
    		PublicKey pubkey = out.address;
    		
    		if (!Crypto.verifySignature(pubkey, tx.getRawDataToSign(i), input.signature)){
    			return false;
    		}
    		
    		unclaimed.add(i, u);
    		
    		inputValues += out.value;
    	}
 
    	return inputValues >= outputValues;
    }
    
    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
    	if (possibleTxs == null){
    		return new Transaction[0];
    	}
    	
    	ArrayList<Transaction> validTxs = new ArrayList<>();
    	for (int i = 0; i < possibleTxs.length; i++) {
    		Transaction tx = possibleTxs[i];
    		if (isValidTx(tx)){
    			validTxs.add(tx);
    			
    			for (int j = 0; j < tx.getInputs().size(); j++){
    				UTXO u = new UTXO(tx.getInput(j).prevTxHash, tx.getInput(j).outputIndex);
    				this.utxoPool.removeUTXO(u);
    			}
    			
    			for (int k = 0; k < tx.getOutputs().size(); k++) {
    				UTXO newUTXO = new UTXO(tx.getHash(), k);
    				this.utxoPool.addUTXO(newUTXO, tx.getOutput(k));
    			}
    			
    		}
    	}

    	return validTxs.toArray(new Transaction[validTxs.size()]);
    }
    

}
