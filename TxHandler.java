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
    	
    	UTXOPool unclaimed = new UTXOPool();
    	
    	double outputValues = 0;
    	double inputValues = 0;
    	
    	for (int i = 0; i < tx.numOutputs(); i++) {
    		Transaction.Output output = tx.getOutput(i);
    		Transaction.Input input = tx.getInput(i);
    		
    		//1 & 3
    		UTXO u = new UTXO(input.prevTxHash, input.outputIndex);
    		if (!utxoPool.contains(u) || unclaimed.contains(u)){
    			return false;
    		}
    		unclaimed.addUTXO(u, output);
    
    		//2
    		if (!Crypto.verifySignature(utxoPool.getTxOutput(u).address, input.prevTxHash, input.signature)){
    			return false;
    		}
    		
    		//4
    		if (output.value < 0) {
    			return false;
    		}
    		
    		//5
    		outputValues += output.value;
    		inputValues += utxoPool.getTxOutput(u).value;
    	}
 
    	return outputValues < inputValues ? false : true;
    }
    
    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
    	Transaction[] validTxs = new Transaction[possibleTxs.length];
    	for (int i = 0; i < possibleTxs.length; i++) {
    		Transaction tx = possibleTxs[i];
    		if (isValidTx(tx)){
    			validTxs[i] = tx;
    			
    			for (int j = 0; j < tx.getOutputs().size(); j++){
    				UTXO u = new UTXO(tx.getInput(j).prevTxHash, tx.getInput(j).outputIndex);
    				utxoPool.addUTXO(u, tx.getOutput(j));
    			}
    			
    		}
    	}

    	return validTxs;
    }
    

}
