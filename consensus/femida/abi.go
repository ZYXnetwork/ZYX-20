package femida

const validatorSetABI = `[{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"validator","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Deposit","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"caller","type":"address"},{"indexed":false,"internalType":"address","name":"validator","type":"address"}],"name":"SlashValidator","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"validator","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"SlashedDeposit","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"caller","type":"address"},{"indexed":false,"internalType":"address","name":"validator","type":"address"}],"name":"SlashedValidator","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"validator","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"unRegisteredValidator","type":"event"},{"inputs":[],"name":"BAN_TIME","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"BLOCK_REWARD","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"INIT_VALIDATORSET_BYTES","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"MAX_VALIDATOR_NUMBERS","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"VALIDATOR_CONTRACT_ADDR","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"VALIDATOR_REG_FEE","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"ZYX_FACTORY_CONTRACT_ADDR","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"allValidators","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"alreadyInit","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"deposit","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[],"name":"getAllValidatorLength","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getValidators","outputs":[{"internalType":"address[]","name":"validator","type":"address[]"},{"internalType":"uint256[]","name":"stake","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"init","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"validator","type":"address"},{"internalType":"address payable","name":"validatorManager","type":"address"},{"internalType":"bytes32","name":"username","type":"bytes32"}],"name":"registerValidator","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"validator","type":"address"}],"name":"slashValidator","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"validator","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"stakeValidator","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"validator","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"unstakeValidator","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"validator","type":"address"},{"internalType":"address payable","name":"validatorManager","type":"address"},{"internalType":"bytes32","name":"username","type":"bytes32"}],"name":"updateValidatorInfo","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"validatorMap","outputs":[{"internalType":"address","name":"validator","type":"address"},{"internalType":"address payable","name":"validatorManager","type":"address"},{"internalType":"contract IZyxDelegatorStakingPool","name":"liquidityPool","type":"address"},{"internalType":"bytes32","name":"username","type":"bytes32"},{"internalType":"uint256","name":"votingPower","type":"uint256"},{"internalType":"bool","name":"isSlashed","type":"bool"},{"internalType":"uint256","name":"timeForUnblock","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"validatorTopList","outputs":[{"internalType":"uint256","name":"size","type":"uint256"},{"internalType":"address","name":"firstElement","type":"address"},{"internalType":"address","name":"lastElement","type":"address"}],"stateMutability":"view","type":"function"}]`